#include <arpa/inet.h>

#include <netinet/in.h>

#include <stdio.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/socket.h>

#include <unistd.h>

#include "postgres.h"
#include "port.h"
#include "utils/guc.h"

#include "access/sysattr.h"
#include "access/twophase.h"

#include "utils/builtins.h"

#include "catalog/indexing.h"
#include "catalog/pg_authid.h"

#include "commands/dbcommands.h"

#include "executor/executor.h"

#include "funcapi.h"

#include "libpq/auth.h"
#include "libpq/ip.h"
#include "miscadmin.h"
#include "storage/proc.h"
#include "storage/ipc.h"
#include "utils/fmgroids.h"
#include "utils/tqual.h"

#include "connection_limits.h"

#if (PG_VERSION_NUM >= 90300)
#include "access/htup_details.h"
#endif

#if (PG_VERSION_NUM >= 90400)
#define SNAPSHOT NULL
#else
#define SNAPSHOT SnapshotNow
#endif

/* default per-object limits */
static int default_per_database = 0;
static int default_per_role = 0;
static int default_per_ip = 0;

/* resets all the counters to 0 */
static void reset_rules(void);

/* load rules from the file */
static void load_rules(void);

static bool load_rule(int line, const char * dbname, const char * user,
					  const char * ip, const char * mask, int limit);

/* simple per-object rules */
static bool rule_is_per_ip(rule_t * rule);
static bool rule_is_per_database(rule_t * rule);
static bool rule_is_per_user(rule_t * rule);

/* check the rules (using pg_stat_activity) */
static void check_rules(Port *port, int status);
static void check_all_rules(void);

/* check that a particular rule matches the database name / username */
static bool rule_matches(rule_t rule, const char * dbname, const char * username,
						 SockAddr ip, char * hostname);

static bool hostname_match(const char *pattern, const char *actual_hostname);

static bool check_ip(SockAddr *raddr, struct sockaddr * addr, struct sockaddr * mask);


static void attach_procarray(void);

static bool backend_info_is_valid(BackendInfo info, volatile PGPROC *proc);

static void backend_update_info(BackendInfo * info, volatile PGPROC *proc,
								char * database, char * role,
								SockAddr socket, char * hostname);

static bool is_super_user(char * rolename);

static void format_address(char * dest, int destlen, struct sockaddr * addr,
						   struct sockaddr * mask);

static bool ipv4eq(struct sockaddr_in * a, struct sockaddr_in * b);
#ifdef HAVE_IPV6
static bool ipv6eq(struct sockaddr_in6 * a, struct sockaddr_in6 * b);
#endif   /* HAVE_IPV6 */

/* allocate space for the rules */
static void pg_limits_shmem_startup(void);

/* saved hook values in case of unload */
static shmem_startup_hook_type			prev_shmem_startup_hook = NULL;
static ClientAuthentication_hook_type	prev_client_auth_hook   = NULL;

/* set of rules and a lock */
static rules_t		 *rules    = NULL;
static BackendInfo	 *backends = NULL;

static ProcArrayStruct *procArray = NULL;

void		_PG_init(void);
void		_PG_fini(void);

/* listing of current state of connection limit rules */

PG_FUNCTION_INFO_V1(connection_limits);

Datum connection_limits(PG_FUNCTION_ARGS);

/*
 * Module load callback
 */
void
_PG_init(void)
{

	/* can be preloaded only from postgresql.conf */
	if (! process_shared_preload_libraries_in_progress)
		elog(ERROR, "connection_limits_shared has to be loaded using "
			    "shared_preload_libraries");

	DefineCustomIntVariable("connection_limits.per_database",
				"Default number of connections per database.",
				"Zero disables this check.",
				&default_per_database,
				0,
				0, MaxBackends,
				PGC_POSTMASTER,
				0,
#if (PG_VERSION_NUM >= 90100)
				NULL,
#endif
				NULL,
				NULL);

	DefineCustomIntVariable("connection_limits.per_user",
				"Default number of connections per user.",
				"Zero disables this check.",
				&default_per_role,
				0,
				0, MaxBackends,
				PGC_POSTMASTER,
				0,
#if (PG_VERSION_NUM >= 90100)
				NULL,
#endif
				NULL,
				NULL);

	DefineCustomIntVariable("connection_limits.per_ip",
				"Default number of connections per IP.",
				"Zero disables this check.",
				&default_per_ip,
				0,
				0, MaxBackends,
				PGC_POSTMASTER,
				0,
#if (PG_VERSION_NUM >= 90100)
				NULL,
#endif
				NULL,
				NULL);

	EmitWarningsOnPlaceholders("connection_limits");

	/*
	 * Request additional shared resources.  (These are no-ops if we're not in
	 * the postmaster process.)  We'll allocate or attach to the shared
	 * resources in pg_limits_shmem_startup().
	 */
	RequestAddinShmemSpace(SEGMENT_SIZE);
	RequestAddinLWLocks(1);	/* single lock guarding the rules state */

	/* Install shared memory startup hook. */
	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = pg_limits_shmem_startup;

	/* Install client authentication hook. */
	prev_client_auth_hook = ClientAuthentication_hook;
	ClientAuthentication_hook = check_rules;

}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	/* Uninstall both hooks. */
	shmem_startup_hook = prev_shmem_startup_hook;
	ClientAuthentication_hook = prev_client_auth_hook;
}

/*
 * Probably the most important part - allocates the shared segment
 * with space for all the rules (and process info), loads the rules
 * from file and performs all the initialization necessary.
 */
static void
pg_limits_shmem_startup()
{

	bool	found = FALSE;
	char   *segment = NULL;

	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	/* Create or attach to the shared memory state (for the rules). */
	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

	segment = ShmemInitStruct(SEGMENT_NAME, SEGMENT_SIZE, &found);

#if (PG_VERSION_NUM < 90000)	/* since 9.0, it always throws an error */
	if (segment == NULL)
		elog(ERROR, "a call to ShmemInitStruct failed (connection_limits)");
#endif

	/* rules are placed first, then the cached backend info */
	rules = (rules_t*)(segment);
	backends = (BackendInfo*)(segment + offsetof(rules_t, rules) + sizeof(rule_t) * MAX_RULES);

	elog(DEBUG1, "initializing segment with connection limit rules (size: %lu B)",
		 SEGMENT_SIZE);

	/* Perform initialization if this is the first time we see the segment. */
	if (! found)
	{
		/* make sure the segment is empty (no rules, ...) */
		memset(rules, 0, SEGMENT_SIZE);

		load_rules();

		elog(DEBUG1, "shared memory segment successfully created, %d rules loaded",
					 rules->n_rules);
	}

	LWLockRelease(AddinShmemInitLock);
}

/*
 * Load rules from the file.
 */
static void
load_rules()
{

	FILE   *file;
	char	line[LINE_MAXLEN];
	char	dbname[NAMEDATALEN], user[NAMEDATALEN], ip[NAMEDATALEN], mask[NAMEDATALEN];
	int		limit;
	int		line_number = 0;

	file = AllocateFile(LIMITS_FILE, "r");
	if (file == NULL)
	{
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("could not open configuration file \"%s\": %m",
						LIMITS_FILE)));

		return;
	}

	while (fgets(line, LINE_MAXLEN, file) != NULL)
	{

		/* remove the comment from the line */
		char * comment = strchr(line, '#');
		if (comment != NULL)
			(*comment) = '\0';

		/* remove all white-space chars from the end of the line */
		comment--;
		while (isspace(comment) && (comment >= line))
		{
			*comment = '\0';
			comment--;
		}

		++line_number;

		/* database user ip mask limit */
		if (sscanf(line, "%s %s %s %s %d", dbname, user, ip, mask, &limit) == 5)
			load_rule(line_number, dbname, user, ip, mask, limit);

		/* database user ip/mask limit */
		else if (sscanf(line, "%s %s %s %d", dbname, user, ip, &limit) == 4)
			load_rule(line_number, dbname, user, ip, NULL, limit);

		/* non-empty line with invalid format */
		else if (strlen(line) > 0)
			elog(WARNING, "invalid rule at line %d", line_number);

	}

	FreeFile(file);

	elog(DEBUG1, "loaded %d connection limit rule(s)", rules->n_rules);

}

static bool
load_rule(int line, const char * dbname, const char * user,
		  const char * ip, const char * mask, int limit)
{
	rule_t * rule;

	/* error if the segment is already full (no space for another rule) */
	if (rules->n_rules == MAX_RULES)
		elog(ERROR, "too many connection limit rules (max: %d)", MAX_RULES);

	/* get space for the next rule */
	rule = &(rules->rules[rules->n_rules]);
	memset(rule, 0, sizeof(rule_t));

	/* reset the rule (no fields) */
	rule->fields = 0;
	rule->limit = limit;
	rule->line = line;

	/* dbname entered */
	if (strcmp("all", dbname) != 0)
	{
		strcpy(rule->database, dbname);
		rule->fields |= CHECK_DBNAME;
	}

	/* username entered */
	if (strcmp("all", user) != 0)
	{
		strcpy(rule->user, user);
		rule->fields |= CHECK_USER;
	}

	/* load the IP (see parse_hba_line in hba.c) */
	if (strcmp("all", ip) != 0)
	{

		int		ret;
		char   *ipcopy ;

		/* IP address parsing */
		struct	addrinfo hints;
		struct	addrinfo * gai_result;

		/* process the IP address (without the mask), or a hostname */

		ipcopy = pstrdup(ip);

		if (strchr(ipcopy, '/'))
			*strchr(ipcopy, '/') = '\0';

		hints.ai_flags = AI_NUMERICHOST;
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = 0;
		hints.ai_protocol = 0;
		hints.ai_addrlen = 0;
		hints.ai_canonname = NULL;
		hints.ai_addr = NULL;
		hints.ai_next = NULL;

		/* try to parse the IP address */
		ret = pg_getaddrinfo_all(ipcopy, NULL, &hints, &gai_result);
		if (ret == 0 && gai_result)
		{
			memcpy(&(rule->ip), gai_result->ai_addr, gai_result->ai_addrlen);
			rule->fields |= CHECK_IP;
		}
		else if (ret == EAI_NONAME)
		{
			strcpy(rule->hostname, ipcopy);
			rule->fields |= CHECK_HOST;
		}
		else
		{
			elog(WARNING,
				 "invalid IP address \"%s\": %s", ipcopy, gai_strerror(ret));
			pfree(ipcopy);
			return false;
		}

		pfree(ipcopy);

		if (gai_result)
			pg_freeaddrinfo_all(hints.ai_family, gai_result);

		/* Get the netmask */
		if (strchr(ip, '/'))
		{
			if (strlen(rule->hostname) != 0)
			{
				elog(WARNING,
					 "specifying both host name and CIDR mask is invalid: \"%s\"", ip);
				return false;
			}
			else if (pg_sockaddr_cidr_mask(&(rule->mask), strchr(ip, '/') + 1, rule->ip.ss_family) < 0)
			{
				elog(WARNING,
					 "invalid CIDR mask in address \"%s\"", ip);
				return false;
			}
		}
		else if (strlen(rule->hostname) == 0)
		{
			if (mask == NULL)
			{
				elog(WARNING,
					 "no mask specified for rule %d", rules->n_rules);
				return false;
			}

			ret = pg_getaddrinfo_all(mask, NULL, &hints, &gai_result);
			if (ret || !gai_result)
			{
				elog(WARNING,
					 "invalid IP mask \"%s\": %s",
					 mask, gai_strerror(ret));

				if (gai_result)
					pg_freeaddrinfo_all(hints.ai_family, gai_result);

				return false;
			}

			memcpy(&rule->mask, gai_result->ai_addr, gai_result->ai_addrlen);
			pg_freeaddrinfo_all(hints.ai_family, gai_result);

			if (rule->ip.ss_family != rule->mask.ss_family)
			{
				elog(WARNING,
					 "IP address and mask do not match");
				return false;
			}
		}
	} /* IP address parsing */

	/* successfully parsed - at least one field needs to be set (increment) */
	if (rule->fields == 0)
	{
		elog(WARNING, "rule on line %d is invalid - no value set", line);
		return false;
	} else
		rules->n_rules += 1;

	return true;

}

static void
check_rules(Port *port, int status)
{

	int r;

	/* index of the backend process */
	int		index;

	/* limits */
	bool	per_user_overriden = false,
			per_database_overriden = false,
			per_ip_overriden = false;

	/* counters */
	int		per_user = 0,
			per_database = 0,
			per_ip = 0;

	/*
	 * Any other plugins which use ClientAuthentication_hook.
	 */
	if (prev_client_auth_hook)
		prev_client_auth_hook(port, status);

	/* No point in checkin the connection rules after failed authentication. */
	if (status != STATUS_OK)
		return;

	/*
	 * Lock ProcArray (serialize the processes, so that we can use the
	 * counters stored in the rule_r struct).
	 *
	 * TODO Use a private array of counters (same number of rules), so
	 *      that we don't need an exclusive lock.
	 */
	LWLockAcquire(ProcArrayLock, LW_EXCLUSIVE);

	/* reset the rule counters */
	reset_rules();

	/* attach the shared segment */
	attach_procarray();

	/*
	 * Perform the actual check - loop through the backends (procArray), and
	 * compare each valid backend against each rule. If it matches, increment
	 * the counter (and if value exceeds the limit, make a failure).
	 *
	 * TODO First check the rules for the current backend, and then only check
	 *      those rules that match (because those are the only rules that may
	 *      be violated by this new connection).
	 */
	for (index = 0; index < procArray->numProcs; index++)
	{

#if (PG_VERSION_NUM <= 90200)
		volatile PGPROC *proc = procArray->procs[index];
#else
		volatile PGPROC *proc = &ProcGlobal->allProcs[procArray->procs[index]];
#endif

		/* do not count prepared xacts */
		if (proc->pid == 0)
			continue;

		/*
		 * If this is the current backend, then update the local info. This
		 * effectively resets info for crashed backends.
		 *
		 * FIXME Maybe this should happen explicitly before the loop.
		 */
		if (proc->backendId == MyBackendId)
		{
			/* lookup remote host name (unless already done) */
			if (! port->remote_hostname)
			{
				char	remote_hostname[NI_MAXHOST];

				if (! pg_getnameinfo_all(&port->raddr.addr, port->raddr.salen,
									remote_hostname, sizeof(remote_hostname),
									NULL, 0, 0))
					port->remote_hostname = pstrdup(remote_hostname);
			}

			/* store the backend info into a cache */
			backend_update_info(&backends[proc->backendId], proc,
								port->database_name, port->user_name,
								port->raddr, port->remote_hostname);
		}

		/* if the backend info is valid, */
		if (backend_info_is_valid(backends[proc->backendId], proc))
		{

			/* see if the database/user/IP matches */
			per_database += (strcmp(backends[proc->backendId].database, port->database_name) == 0) ? 1 : 0;
			per_user     += (strcmp(backends[proc->backendId].role, port->user_name) == 0) ? 1 : 0;
			per_ip       += (memcmp(&backends[proc->backendId].socket, &port->raddr, sizeof(SockAddr)) == 0) ? 1 : 0;

			/* check all the rules for this backend */
			for (r = 0; r < rules->n_rules; r++)
			{

				/*
				 * The rule has to be matched by both the current and new session, otherwise
				 * it can't be violated by the new one.
				 *
				 * FIXME This repeatedly checks all the rules for the current backend, which is not
				 *       needed. We only need to do this check (for the new session) once, and then
				 *       walk only the rules that match it. Althouth that may not detect the
				 *       default rules (per db, ...).
				 */
				if (rule_matches(rules->rules[r], port->database_name, port->user_name, port->raddr, port->remote_host))
				{

					/* check if this rule overrides per-db, per-user or per-ip limits */
					per_database_overriden |= rule_is_per_database(&rules->rules[r]);
					per_user_overriden     |= rule_is_per_user(&rules->rules[r]);
					per_ip_overriden       |= rule_is_per_ip(&rules->rules[r]);

					/* Check the rule for a existing backend (we assume it's valid thanks to backend_info_is_valid()). */
					if (rule_matches(rules->rules[r], backends[proc->backendId].database,
									 backends[proc->backendId].role, backends[proc->backendId].socket,
									 backends[proc->backendId].hostname))
					{

						/* increment the match count for this rule */
						++rules->rules[r].count;

						/*
						 * We're looping over all backends (including the current backend), so the
						 * rule is only violated if the limit is actually exceeded.
						 */
						if (rules->rules[r].count > rules->rules[r].limit)
						{

							if (! is_super_user(port->user_name))
								elog(ERROR, "connection limit reached (rule %d, line %d, limit %d)",
											r, rules->rules[r].line, rules->rules[r].limit);
							else
								elog(WARNING, "connection limit reached (rule %d, line %d, limit %d), but the user is a superuser",
											r, rules->rules[r].line, rules->rules[r].limit);

						}
					}
				}

			}
		}
	}

	/*
	 * Check the per-db/user/IP limits, unless there was an exact rule overriding
	 * the defaults for that object, or unless the default was disabled (set to 0).
	 */

	/* check per-database limit */
	if ((! per_database_overriden) && (default_per_database != 0) && (per_database > default_per_database))
	{
		if (! is_super_user(port->user_name))
			elog(ERROR, "per-database connection limit reached (limit %d)",
				 default_per_database);
		else
			elog(WARNING, "per-database  limit reached (limit %d), but the user is a superuser",
				 default_per_database);
	}

	/* check per-user limit */
	if ((! per_user_overriden) && (default_per_role != 0) && (per_user > default_per_role))
	{
		if (! is_super_user(port->user_name))
			elog(ERROR, "per-user connection limit reached (limit %d)",
				 default_per_role);
		else
			elog(WARNING, "per-user connection limit reached (limit %d), but the user is a superuser",
				 default_per_role);
	}

	/* check per-IP limit */
	if ((! per_ip_overriden) && (default_per_ip != 0) && (per_ip > default_per_ip))
	{
		if (! is_super_user(port->user_name))
			elog(ERROR, "per-IP connection limit reached (limit %d)",
				 default_per_ip);
		else
			elog(WARNING, "per-IP connection limit reached (limit %d), but the user is a superuser",
				 default_per_ip);
	}

	LWLockRelease(ProcArrayLock);

}

/*
 * Check rules for all the (valid) backends.
 *
 * TODO This pretty much replicates most check_rules() functionality, so maybe
 *      this could be either merged or refactored to reuse some code.
 *
 * TODO This is called only from the connection_limits(), and that may hold the
 *      lock for quite long. Move the lock/release here, and copy all the data
 *      instead of looping through the shared memory.
 */
static void
check_all_rules(void)
{
	/* index of the process */
	int	index;
	int r;

	for (index = 0; index < procArray->numProcs; index++)
	{

#if (PG_VERSION_NUM <= 90200)
			volatile PGPROC *proc = procArray->procs[index];
#else
			volatile PGPROC *proc = &ProcGlobal->allProcs[procArray->procs[index]];
#endif

		/* do not count prepared xacts */
		if (proc->pid == 0)
			continue;

		/* do this only for valid backends */
		if (backend_info_is_valid(backends[proc->backendId], proc))
		{

			/* FIXME This should probably refresh the hostname (using pg_getnameinfo_all) */

			/* check all the rules for this backend */
			for (r = 0; r < rules->n_rules; r++)
			{

				/* check the rule for a backend - if the PID is different, the backend is
				* waiting on the lock (and will be processed soon) */
				if (rule_matches(rules->rules[r], backends[proc->backendId].database,
									backends[proc->backendId].role, backends[proc->backendId].socket,
									backends[proc->backendId].hostname))

					/* increment the count */
					++rules->rules[r].count;

			}
		}
	}
}

/*
 * Check whether a rule matches the provided info.
 */
static bool
rule_matches(rule_t rule, const char * dbname, const char * user, SockAddr ip, char * hostname) {

	/* only one of the CHECK_IP / CHECK_HOST flags can be set */
	Assert(!((rule.fields & CHECK_IP) && (rule.fields & CHECK_HOST)));

	/* dbname does not match */
	if ((rule.fields & CHECK_DBNAME) && (strcmp(rule.database, dbname) != 0))
		return false;

	/* username does not match */
	if ((rule.fields & CHECK_USER) && (strcmp(rule.user, user) != 0))
		return false;

	/* check the IP address (mask etc.) */
	if (rule.fields & CHECK_IP)
		if (! check_ip(&ip, (struct sockaddr *)&rule.ip, (struct sockaddr *)&rule.mask))
			return false;

	if ((rule.fields & CHECK_HOST) && (strcmp(rule.hostname, hostname) != 0))
	{

		int ret;
		bool found = false;
		struct addrinfo *gai_result, *gai;

		/* was the reverse lookup successfull? */
		if (hostname && (! hostname_match(rule.hostname, hostname)))
			return false;

		ret = getaddrinfo(rule.hostname, NULL, NULL, &gai_result);

		if (ret != 0)
			ereport(WARNING,
					(errmsg("could not translate host name \"%s\" to address: %s",
							rule.hostname, gai_strerror(ret))));

		for (gai = gai_result; gai; gai = gai->ai_next)
		{

			if (gai->ai_addr->sa_family == ip.addr.ss_family)
			{

				if (gai->ai_addr->sa_family == AF_INET)
				{
					if (ipv4eq((struct sockaddr_in *) gai->ai_addr,
							(struct sockaddr_in *) & ip.addr))
					{
						found = true;
						break;
					}
				}
#ifdef HAVE_IPV6
				else if (gai->ai_addr->sa_family == AF_INET6)
				{
					if (ipv6eq((struct sockaddr_in6 *) gai->ai_addr,
							(struct sockaddr_in6 *) & ip.addr))
					{
						found = true;
						break;
					}
				}
#endif
			}
		}

		if (gai_result)
			freeaddrinfo(gai_result);

		if (! found) {
			elog(WARNING, "pg_hba.conf host name \"%s\" rejected because address "
						  "resolution did not return a match with IP address of client",
						  rule.hostname);
			return false;
		}
	}

	return true;

}

/*
 * TODO rename to reset_rules_counters() to better describe the purpose
 */
static void
reset_rules() {
	int i;
	for (i = 0; i < rules->n_rules; i++)
		rules->rules[i].count = 0;
}

/*
 * Check to see if a connecting IP matches the given address and netmask.
 *
 * code copied from ./src/backend/libpq/hba.c:670 (or nearby)
 */
static bool
check_ip(SockAddr *raddr, struct sockaddr * addr, struct sockaddr * mask)
{
	if (raddr->addr.ss_family == addr->sa_family)
	{
		/* Same address family */
		if (!pg_range_sockaddr(&raddr->addr,
					   (struct sockaddr_storage *) addr,
					   (struct sockaddr_storage *) mask))
			return false;
	}
#ifdef HAVE_IPV6
	else if (addr->sa_family == AF_INET &&
			 raddr->addr.ss_family == AF_INET6)
	{
		/*
		 * If we're connected on IPv6 but the file specifies an IPv4 address
		 * to match against, promote the latter to an IPv6 address before
		 * trying to match the client's address.
		 */
		struct sockaddr_storage addrcopy,
					maskcopy;

		memcpy(&addrcopy, &addr, sizeof(addrcopy));
		memcpy(&maskcopy, &mask, sizeof(maskcopy));
		pg_promote_v4_to_v6_addr(&addrcopy);
		pg_promote_v4_to_v6_mask(&maskcopy);

		if (!pg_range_sockaddr(&raddr->addr, &addrcopy, &maskcopy))
			return false;
	}
#endif   /* HAVE_IPV6 */
	else
	{
		/* Wrong address family, no IPV6 */
		return false;
	}

	return true;
}

/* Attach the procArray segment (array of backends) or fail. */
static void
attach_procarray()
{

	bool		found;

	/* already attached
	 *
	 * FIXME How could this happen? It's static and attached only once, right?
	 *       If this gets called twice, it's probably an error (worth a WARNING
	 *       at least, or maybe an ERROR). Maybe while unloading/reloading the
	 *       module, somehow?
	 */
	if (procArray != NULL)
		return;

	/* Create or attach to the ProcArray shared structure */
	procArray = (ProcArrayStruct *) ShmemInitStruct("Proc Array",
													add_size(offsetof(ProcArrayStruct, procs),
															 mul_size(sizeof(int),
																	  PROCARRAY_MAXPROCS)),
                                                &found);

	if (! found)
		elog(FATAL, "the Proc Array shared segment was not found");

}

/*
 * Update cached info of a backend (so that we can check it quickly, without
 * excessive number of lookups etc.).
 */
static void
backend_update_info(BackendInfo * info, volatile PGPROC *proc,
					char * database, char * role,
					SockAddr socket, char * hostname)
{
	info->pid = proc->pid;
	info->backendId = proc->backendId;

	strcpy(info->database, database);
	strcpy(info->role, role);
	memcpy(&info->socket, &socket, sizeof(SockAddr));

	/* update the hostname (if it's NULL, use empty string) */
	if (hostname != NULL)
		strcpy(info->hostname, hostname);
	else
		info->hostname[0] = '\0';
}

/*
 * Check that the cached backend info is still valid, i.e. if the info
 * still matches.
 *
 * This checks just the PID and backendId, although even a PID would be
 * enough, probably. We can't check databaseId/roleId at this moment,
 * because we don't have this info yet (at least not stored in PGPROC).
 * This seems to work fine even for closed/crashed backends.
 */
static bool
backend_info_is_valid(BackendInfo info, volatile PGPROC *proc)
{
	return ((info.pid == proc->pid) &&
			(info.backendId == proc->backendId));
}

/*
* GetRoleTupleByOid -- as above, but search by role OID
*/
static HeapTuple
GetRoleTupleByName(const char * rolename)
{
	HeapTuple tuple;
	Relation relation;
	SysScanDesc scan;
	ScanKeyData key[1];

	/*
	* form a scan key
	*/
	ScanKeyInit(&key[0],
				Anum_pg_authid_rolname,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(rolename));

	/*
	* Open pg_authid and fetch a tuple. Force heap scan if we haven't yet
	* built the critical shared relcache entries (i.e., we're starting up
	* without a shared relcache cache file).
	*/
	relation = heap_open(AuthIdRelationId, AccessShareLock);
	scan = systable_beginscan(relation, AuthIdRolnameIndexId,
							criticalSharedRelcachesBuilt,
							SNAPSHOT,
							1, key);

	tuple = systable_getnext(scan);

	/* Must copy tuple before releasing buffer */
	if (HeapTupleIsValid(tuple))
		tuple = heap_copytuple(tuple);

	/* all done */
	systable_endscan(scan);
	heap_close(relation, AccessShareLock);

	return tuple;
}

static bool
is_super_user(char * rolename)
{

	HeapTuple tuple = GetRoleTupleByName(rolename);
	Form_pg_authid roleform;

	if (!HeapTupleIsValid(tuple))
		elog(FATAL, "role '%s' does not exist", rolename);

	roleform = (Form_pg_authid) GETSTRUCT(tuple);

	return (roleform->rolsuper);

}

/* TODO Consider switching these trivial functions into macros. */

static bool
rule_is_per_user(rule_t * rule)
{
	return (rule->fields == CHECK_USER);
}

static bool
rule_is_per_database(rule_t * rule)
{
	return (rule->fields == CHECK_DBNAME);
}

static bool
rule_is_per_ip(rule_t * rule)
{
	return (rule->fields == CHECK_IP);
}


Datum
connection_limits(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	TupleDesc	   tupdesc;
	AttInMetadata   *attinmeta;

	/* init on the first call */
	if (SRF_IS_FIRSTCALL())
	{

		MemoryContext oldcontext;

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		LWLockAcquire(ProcArrayLock, LW_EXCLUSIVE);

		reset_rules();
		check_all_rules();

		/* number of rules */
		funcctx->max_calls = rules->n_rules;

		/* Build a tuple descriptor for our result type */
		if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("function returning record called in context "
							"that cannot accept type record")));

		/*
		 * generate attribute metadata needed later to produce tuples from raw
		 * C strings
		 */
		attinmeta = TupleDescGetAttInMetadata(tupdesc);
		funcctx->attinmeta = attinmeta;
		funcctx->tuple_desc = tupdesc;

		/* switch back to the old context */
		MemoryContextSwitchTo(oldcontext);

	}

	/* init the context */
	funcctx = SRF_PERCALL_SETUP();

	/* check if we have more data */
	if (funcctx->max_calls > funcctx->call_cntr)
	{
		HeapTuple	   tuple;
		Datum		   result;
		Datum		   values[6];
		bool			nulls[6];

		rule_t * rule = &(rules->rules[funcctx->call_cntr]);

		memset(nulls, 0, sizeof(nulls));

		/* rule line */
		values[0] = UInt32GetDatum(rule->line);

		/* database */
		if (rule->fields & CHECK_DBNAME)
			values[1] = CStringGetTextDatum(rule->database);
		else
			nulls[1] = TRUE;

		/* username */
		if (rule->fields & CHECK_USER)
			values[2] = CStringGetTextDatum(rule->user);
		else
			nulls[2] = TRUE;

		/* hostname or IP address */
		if (rule->fields & CHECK_HOST)
			values[3] = CStringGetTextDatum(rule->hostname);
		else if (rule->fields & CHECK_IP)
		{
			char buffer[256];
			memset(buffer, 0, 256);
			format_address(buffer, 256, (struct sockaddr*)&rule->ip, (struct sockaddr*)&rule->mask);
			values[3] = CStringGetTextDatum(buffer);
		}
		else
			nulls[3] = TRUE;

		/* count and limit */
		values[4] = UInt32GetDatum(rule->count);
		values[5] = UInt32GetDatum(rule->limit);

		/* Build and return the tuple. */
		tuple = heap_form_tuple(funcctx->tuple_desc, values, nulls);

		/* make the tuple into a datum */
		result = HeapTupleGetDatum(tuple);

		/* Here we want to return another item: */
		SRF_RETURN_NEXT(funcctx, result);

	}
	else
	{
		/* lock ProcArray (serialize the processes) */
		LWLockRelease(ProcArrayLock);

		/* Here we are done returning items and just need to clean up: */
		SRF_RETURN_DONE(funcctx);
	}
}


static void
format_address(char * dest, int destlen, struct sockaddr * addr, struct sockaddr * mask)
{
	int		ret,
			len,
			pos = 0;

	char	buffer[256];

	switch (addr->sa_family)
	{
		case AF_INET:
			len = sizeof(struct sockaddr_in);
			break;
#ifdef HAVE_IPV6
		case AF_INET6:
			len = sizeof(struct sockaddr_in6);
			break;
#endif
		default:
			len = sizeof(struct sockaddr_storage);
			break;
	}

	ret = getnameinfo(addr, len, buffer, sizeof(buffer), NULL, 0, NI_NUMERICHOST);

	if (ret != 0)
		elog(WARNING, "[unknown: family %d]", addr->sa_family);
	else
	{
		strcpy(dest, buffer);
		pos = strlen(buffer);
		dest[pos++] = '/';
	}

	ret = getnameinfo(mask, len, buffer, sizeof(buffer), NULL, 0, NI_NUMERICHOST);

	if (ret != 0)
		elog(WARNING, "[unknown: family %d]", mask->sa_family);
	else
		strcpy(&dest[pos], buffer);

}


/*
 * Check whether host name matches pattern.
 */
static bool
hostname_match(const char *pattern, const char *actual_hostname)
{
	if (pattern[0] == '.')		/* suffix match */
	{
		size_t		plen = strlen(pattern);
		size_t		hlen = strlen(actual_hostname);

		if (hlen < plen)
			return false;

		return (pg_strcasecmp(pattern, actual_hostname + (hlen - plen)) == 0);
	}
	else
		return (pg_strcasecmp(pattern, actual_hostname) == 0);
}


static bool
ipv4eq(struct sockaddr_in * a, struct sockaddr_in * b)
{
	return (a->sin_addr.s_addr == b->sin_addr.s_addr);
}

#ifdef HAVE_IPV6

static bool
ipv6eq(struct sockaddr_in6 * a, struct sockaddr_in6 * b)
{
	int			i;

	for (i = 0; i < 16; i++)
		if (a->sin6_addr.s6_addr[i] != b->sin6_addr.s6_addr[i])
			return false;

	return true;
}
#endif   /* HAVE_IPV6 */
