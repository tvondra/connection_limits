#include <stdio.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/socket.h>

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

static int default_per_database = 0;
static int default_per_role = 0;
static int default_per_ip = 0;

/* allocates space for the rules */
static void pg_limits_shmem_startup(void);

/* check the rules (using pg_stat_activity) */
static void check_rules(Port *port, int status);
static void check_all_rules(void);

/* resets the counters to 0 */
static void reset_rules(void);

/* check that a particular rule matches the database name / username */
static bool rule_matches(rule_t rule, const char * dbname, const char * username,
			 SockAddr ip, char * hostname);

/* count rules in the config file */
static int number_of_rules(void);

/* load rules from the file */
static void load_rules(void);

static bool load_rule(int line, const char * dbname, const char * user,
		      const char * ip, const char * mask, int limit);

static bool check_ip(SockAddr *raddr, struct sockaddr * addr, struct sockaddr * mask);

static bool attach_procarray(void);

static bool backend_info_is_valid(BackendInfo info, pid_t pid);
static void backend_update_info(BackendInfo * info, pid_t pid, char * database,
				char * role, SockAddr socket, char * hostname);

static bool is_super_user(char * rolename);

static bool rule_is_per_ip(rule_t * rule);
static bool rule_is_per_database(rule_t * rule);
static bool rule_is_per_user(rule_t * rule);

static void format_address(char * dest, int destlen, struct sockaddr * addr,
			   struct sockaddr * mask);

static bool hostname_match(const char *pattern, const char *actual_hostname);

static bool ipv4eq(struct sockaddr_in * a, struct sockaddr_in * b);
#ifdef HAVE_IPV6
static bool ipv6eq(struct sockaddr_in6 * a, struct sockaddr_in6 * b);
#endif   /* HAVE_IPV6 */

/* Saved hook values in case of unload */
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;

/* Original Hook */
static ClientAuthentication_hook_type prev_client_auth_hook = NULL;

/* set of rules and a lock */
static rules_t * rules = NULL;
static BackendInfo * backends = NULL;

static ProcArrayStruct *procArray = NULL;

void		_PG_init(void);
void		_PG_fini(void);

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
	RequestAddinLWLocks(1);

	/* Install hooks. */
	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = pg_limits_shmem_startup;
	
	/* Install Hooks */
	prev_client_auth_hook = ClientAuthentication_hook;
	ClientAuthentication_hook = check_rules;

}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	/* Uninstall hooks. */
	shmem_startup_hook = prev_shmem_startup_hook;
}

/* This is probably the most important part - allocates the shared 
 * segment, initializes it etc. */
static
void pg_limits_shmem_startup() {

	bool	found = FALSE;
	char   *segment = NULL;
	int n;
	
	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();
	
	/*
	 * Create or attach to the shared memory state, including hash table
	 */
	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);
	
	n = number_of_rules();
	
	if (n > MAX_RULES) {
		elog(ERROR, "too many connection limit rules (file: %d, max: %d)",
			 n, MAX_RULES);
	}

	segment = ShmemInitStruct(SEGMENT_NAME, SEGMENT_SIZE, &found);

	/* set the pointers */
	rules = (rules_t*)(segment);
	backends = (BackendInfo*)(segment + sizeof(rule_t) * (MAX_RULES-1) + sizeof(rules_t));
	
	elog(DEBUG1, "initializing segment with connection limit rules (size: %lu B)",
		 SEGMENT_SIZE);

	if (! found) {
		
		memset(rules, 0, SEGMENT_SIZE);
		
		load_rules();
		
		elog(DEBUG1, "shared memory segment (query buffer) successfully created");
		
	}

	LWLockRelease(AddinShmemInitLock);
	
}

static
int number_of_rules() {
	
	FILE   *file;
	char	line[LINE_MAXLEN];
	char	dbname[NAMEDATALEN], user[NAMEDATALEN], mask[NAMEDATALEN], ip[NAMEDATALEN];
	int	 limit;
	int	 n = 0;

	file = AllocateFile(LIMITS_FILE, "r");
	if (file == NULL)
	{
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("could not open configuration file \"%s\": %m",
						LIMITS_FILE)));

		return 0;
	}
	
	while (fgets(line, LINE_MAXLEN, file) != NULL) {
		if (sscanf(line, "%s %s %s %d", dbname, user, ip, &limit) == 4) {
			n++;
		} else if (sscanf(line, "%s %s %s %s %d", dbname, user, ip, mask, &limit) == 5) {
			n++;
		}
	}

	FreeFile(file);
	
	return n;
	
}

static
void load_rules(void) {
	
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
	
	while (fgets(line, LINE_MAXLEN, file) != NULL) {

		/* remove comment from the line */
		char * comment = strchr(line, '#');
		if (comment != NULL) {
			(*comment) = '\0';
		}
		
		++line_number;
		
		if (sscanf(line, "%s %s %s %s %d", dbname, user, ip, mask, &limit) == 5) {
			
			/* database user ip mask limit */
			load_rule(line_number, dbname, user, ip, mask, limit);
			
		} else if (sscanf(line, "%s %s %s %d", dbname, user, ip, &limit) == 4) {

			/* database user ip/mask limit */
			load_rule(line_number, dbname, user, ip, NULL, limit);
			
		} else if (strlen(line) > 0) {
			
			// FIXME check errors
			elog(WARNING, "invalid rule at line %d", line_number);
			
		}
	}

	FreeFile(file);
	
	elog(NOTICE, "loaded %d connection limit rule(s)", rules->n_rules);

}

static
bool load_rule(int line, const char * dbname, const char * user, const char * ip,
	       const char * mask, int limit)
{
	/* get next rule */
	rule_t * rule = &(rules->rules[rules->n_rules]);
	memset(rule, 0, sizeof(rule_t));
	
	/* reset the rule (no fields) */
	rule->fields = 0;
	rule->limit = limit;
	rule->line = line;
	
	/* dbname entered */
	if (strcmp("all", dbname) != 0) {
		strcpy(rule->database, dbname);
		rule->fields |= CHECK_DBNAME;
	}
	
	/* username entered */
	if (strcmp("all", user) != 0) {
		strcpy(rule->user, user);
		rule->fields |= CHECK_USER;
	}
	
	/* load the IP (see parse_hba_line in hba.c) */
	if (strcmp("all", ip) != 0) {

		int ret;
		char * ipcopy ;
		
		/* IP address parsing */
		struct addrinfo hints;
		struct addrinfo * gai_result;
		
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
			if (mask == NULL) {
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
	if (rule->fields == 0) {
		elog(WARNING, "rule on line %d is invalid - no value set", line);
		return false;
	} else {
		rules->n_rules += 1;
	}
	
	return true;
	
}

static
void check_rules(Port *port, int status)
{

	int r;

	/*
	 * Any other plugins which use ClientAuthentication_hook.
	 */
	if (prev_client_auth_hook)
		prev_client_auth_hook(port, status);

	/*
	 * Inject a short delay if authentication failed.
	 */
	if (status == STATUS_OK)
	{
		/* index of the process */
		int			index;
		
		/* limits */
		bool		per_user_overriden = false,
					per_database_overriden = false,
					per_ip_overriden = false;
		
		/* counters */
		int			per_user = 0,
					per_database = 0,
					per_ip = 0;

		/* lock ProcArray (serialize the processes) */
		LWLockAcquire(ProcArrayLock, LW_EXCLUSIVE);

		/* reset the rules */
		reset_rules();
		
		/* attach the shared segment */
		attach_procarray();
		
		for (index = 0; index < procArray->numProcs; index++)
		{

#if (PG_VERSION_NUM <= 90200)
			volatile PGPROC *proc = procArray->procs[index];
#else
			volatile PGPROC *proc = &ProcGlobal->allProcs[procArray->procs[index]];
#endif

			if (proc->pid == 0) {
				/* do not count prepared xacts */
				continue;
			} else {
				
				/* if this is the backend, then update the local info */
				if (proc->backendId == MyBackendId) {
					
					/* Lookup remote host name if not already done */
					if (! port->remote_hostname) {
						
						char	remote_hostname[NI_MAXHOST];
						
						if (! pg_getnameinfo_all(&port->raddr.addr, port->raddr.salen,
											remote_hostname, sizeof(remote_hostname),
											NULL, 0,
											0)) {
							
							port->remote_hostname = pstrdup(remote_hostname);
						}
						
					}
					
					backend_update_info(&backends[proc->backendId], proc->pid,
										port->database_name, port->user_name, port->raddr,
										port->remote_hostname);
				}
				
				/* do this only if the backend is valid */
				if (backend_info_is_valid(backends[proc->backendId], proc->pid)) {
					
					/* increment per_database, per_user and per_ip counters */
					per_database += (strcmp(backends[proc->backendId].database, port->database_name) == 0) ? 1 : 0;
					per_user     += (strcmp(backends[proc->backendId].role, port->user_name) == 0) ? 1 : 0;
					per_database += (memcmp(&backends[proc->backendId].socket, &port->raddr, sizeof(SockAddr)) == 0) ? 1 : 0;
				
					/* check all the rules for this backend */
					for (r = 0; r < rules->n_rules; r++) {
						
						/* the rule has to matche both the backend and the current session
						* at the same time */
						if (rule_matches(rules->rules[r], port->database_name, port->user_name, port->raddr, port->remote_host)) {
							
							/* check if this rule overrides per-db, per-user or per-ip limits */
							per_database_overriden = per_database_overriden || rule_is_per_database(&rules->rules[r]);
							per_user_overriden     = per_user_overriden || rule_is_per_user(&rules->rules[r]);
							per_ip_overriden       = per_ip_overriden || rule_is_per_ip(&rules->rules[r]);
							
							/* check the rule for a backend - if the PID is different, the backend is
							* waiting on the lock (and will be processed soon) */
							if (rule_matches(rules->rules[r], backends[proc->backendId].database,
										backends[proc->backendId].role, backends[proc->backendId].socket,
										backends[proc->backendId].hostname)) {
										
								/* increment the count */
								++rules->rules[r].count;
							
								/* the current backend is not if pg_stat_backends yet, so equality
								* actually means the limit was crossed */
								if (rules->rules[r].count > rules->rules[r].limit) {
									
									if (! is_super_user(port->user_name)) {
										elog(ERROR, "connection limit reached (rule %d, line %d, limit %d)",
													r, rules->rules[r].line, rules->rules[r].limit);
									} else {
										elog(WARNING, "connection limit reached (rule %d, line %d, limit %d), but the user is a superuser",
													r, rules->rules[r].line, rules->rules[r].limit);
									}
									
								} /* limit reached */
								
							} /* rule_matches(record from pg_stat_activity) */
							
						} /* rule_matches(this backend) */
						
					} /* for (r = 0; r < rules->n_rules; r++) */
					
				} /* if (backend_is_valid(...)) */
			}
		}
		
		/* check per-database limit */
		if ((! per_database_overriden) && (default_per_database != 0) && (per_database > default_per_database)) {
			if (! is_super_user(port->user_name)) {
				elog(ERROR, "per-database connection limit reached (limit %d)",
					 default_per_database);
			} else {
				elog(WARNING, "per-database  limit reached (limit %d), but the user is a superuser",
					 default_per_database);
			}
		}
		
		/* check per-user limit */
		if ((! per_user_overriden) && (default_per_role != 0) && (per_user > default_per_role)) {
			if (! is_super_user(port->user_name)) {
				elog(ERROR, "per-user connection limit reached (limit %d)",
					 default_per_role);
			} else {
				elog(WARNING, "per-user connection limit reached (limit %d), but the user is a superuser",
					 default_per_role);
			}
		}
		
		/* check per-IP limit */
		if ((! per_ip_overriden) && (default_per_ip != 0) && (per_ip > default_per_ip)) {
			if (! is_super_user(port->user_name)) {
				elog(ERROR, "per-IP connection limit reached (limit %d)",
					 default_per_ip);
			} else {
				elog(WARNING, "per-IP connection limit reached (limit %d), but the user is a superuser",
					 default_per_ip);
			}
		}

		LWLockRelease(ProcArrayLock);

	} /* (status == STATUS_OK) */

}

static
void check_all_rules(void)
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

		if (proc->pid == 0) {
			/* do not count prepared xacts */
			continue;
		} else {
		
			/* do this only if the backend is valid */
			if (backend_info_is_valid(backends[proc->backendId], proc->pid)) {
				
				/* check all the rules for this backend */
				for (r = 0; r < rules->n_rules; r++) {
					
					/* FIXME This should probably refresh the hostname (using pg_getnameinfo_all) */
					
					/* check the rule for a backend - if the PID is different, the backend is
					* waiting on the lock (and will be processed soon) */
					if (rule_matches(rules->rules[r], backends[proc->backendId].database,
										backends[proc->backendId].role, backends[proc->backendId].socket,
										backends[proc->backendId].hostname)) {
									
						/* increment the count */
						++rules->rules[r].count;
						
					} /* rule_matches(record from pg_stat_activity) */
					
				} /* for (r = 0; r < rules->n_rules; r++) */
				
			} /* if (backend_is_valid(...)) */
		}
		
	} /* for (index = 0; index < procArray->numProcs; index++) */

}

static
bool rule_matches(rule_t rule, const char * dbname, const char * user, SockAddr ip, char * hostname) {
	
	/* dbname does not match */
	if ((rule.fields & CHECK_DBNAME) && (strcmp(rule.database, dbname) != 0)) {
		return false;
	}
	
	/* username does not match */
	if ((rule.fields & CHECK_USER) && (strcmp(rule.user, user) != 0)) {
		return false;
	}
	
	/* check the IP address (mask etc.) */
	if (rule.fields & CHECK_IP) {
		
		if (! check_ip(&ip, (struct sockaddr *)&rule.ip, (struct sockaddr *)&rule.mask)) {
			return false;
		}
		
	} else if ((rule.fields & CHECK_HOST) && (strcmp(rule.hostname, hostname) != 0)) {
		
		/* was the reverse lookup successfull? */
		if (hostname && (! hostname_match(rule.hostname, hostname))) {
			return false;
		} else {
			
			bool found = false;
			struct addrinfo *gai_result, *gai;
			
			int ret = getaddrinfo(rule.hostname, NULL, NULL, &gai_result);
			
			if (ret != 0) {
				ereport(WARNING,
						(errmsg("could not translate host name \"%s\" to address: %s",
								rule.hostname, gai_strerror(ret))));
			}

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
				elog(WARNING, "pg_hba.conf host name \"%s\" rejected because address resolution did not return a match with IP address of client",
					rule.hostname);
				return false;
			}
		}
	}

	
	return true;
	
}

static
void reset_rules() {
	int i;
	for (i = 0; i < rules->n_rules; i++) {
		rules->rules[i].count = 0;
	}
}

/*
 * Check to see if a connecting IP matches the given address and netmask.
 */
/* ./src/backend/libpq/hba.c:670 */
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

static
bool attach_procarray() {
	
	bool		found;
	
	/* already attached */
	if (procArray != NULL) {
		return true;
	}

	/* Create or attach to the ProcArray shared structure */
	procArray = (ProcArrayStruct *)
                ShmemInitStruct("Proc Array",
                                                add_size(offsetof(ProcArrayStruct, procs),
                                                                 mul_size(sizeof(int),
                                                                                  PROCARRAY_MAXPROCS)),
                                                &found);
	if (! found) {
		elog(ERROR, "the Proc Array shared segment was not found");
		return false;
	}
	
	return true;

}

/* 
 */
static void backend_update_info(BackendInfo * info, pid_t pid, char * database, char * role, SockAddr socket, char * hostname) {
	
	info->pid = pid;
	strcpy(info->database, database);
	strcpy(info->role, role);
	memcpy(&info->socket, &socket, sizeof(SockAddr));
	
	/* update the hostname, but carefully as it may be NULL */
	if (hostname != NULL) {
		strcpy(info->hostname, hostname);
	} else {
		info->hostname[0] = '\0';
	}
	
}

static bool backend_info_is_valid(BackendInfo info, pid_t pid) {
	return (info.pid == pid);
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

static
bool is_super_user(char * rolename) {

	HeapTuple tuple = GetRoleTupleByName(rolename);
	Form_pg_authid roleform;

	if (!HeapTupleIsValid(tuple)) {
		elog(FATAL, "role %s does not exist", rolename);
	}

	roleform = (Form_pg_authid) GETSTRUCT(tuple);

	return (roleform->rolsuper);

}

static
bool rule_is_per_user(rule_t * rule) {
	return (rule->fields == CHECK_USER);
}

static
bool rule_is_per_database(rule_t * rule) {
	return (rule->fields == CHECK_DBNAME);
}

static
bool rule_is_per_ip(rule_t * rule) {
	return (rule->fields == CHECK_IP);
}


Datum
connection_limits(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	TupleDesc	   tupdesc;
	AttInMetadata   *attinmeta;

	/* init on the first call */
	if (SRF_IS_FIRSTCALL()) {
		
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
		if (rule->fields & CHECK_DBNAME) {
			values[1] = CStringGetTextDatum(rule->database);
		} else {
			nulls[1] = TRUE;
		}
		
		/* username */
		if (rule->fields & CHECK_USER) {
			values[2] = CStringGetTextDatum(rule->user);
		} else {
			nulls[2] = TRUE;
		}
		
		/* hostname or IP address */
		if (rule->fields & CHECK_HOST) {
			values[3] = CStringGetTextDatum(rule->hostname);
		} else if (rule->fields & CHECK_IP) {
			char buffer[256];
			memset(buffer, 0, 256);
			format_address(buffer, 256, (struct sockaddr*)&rule->ip, (struct sockaddr*)&rule->mask);
			values[3] = CStringGetTextDatum(buffer);
		} else {
			nulls[3] = TRUE;
		}
		
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


static void format_address(char * dest, int destlen, struct sockaddr * addr, struct sockaddr * mask)
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
	
	if (ret != 0) {
		elog(WARNING, "[unknown: family %d]", addr->sa_family);
	} else {
		strcpy(dest, buffer);
		pos = strlen(buffer);
		dest[pos++] = '/';
	}

	ret = getnameinfo(mask, len, buffer, sizeof(buffer), NULL, 0, NI_NUMERICHOST);
	
	if (ret != 0) {
		elog(WARNING, "[unknown: family %d]", mask->sa_family);
	} else {
		strcpy(&dest[pos], buffer);
	}
	
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
