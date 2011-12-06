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

#include "access/sysattr.h"
#include "access/twophase.h"

#include "catalog/indexing.h"
#include "catalog/pg_authid.h"

#include "commands/dbcommands.h"

#include "executor/executor.h"

#include "libpq/auth.h"
#include "libpq/ip.h"
#include "miscadmin.h"
#include "storage/proc.h"
#include "storage/ipc.h"
#include "utils/fmgroids.h"
#include "utils/tqual.h"

#include "connection_limits.h"

/* allocates space for the rules */
static void pg_limits_shmem_startup(void);

/* check the rules (using pg_stat_activity) */
static void check_rules(Port *port, int status);

/* resets the counters to 0 */
static void reset_rules(void);

/* check that a particular rule matches the database name / username */
static bool rule_matches(rule_t rule, const char * dbname, const char * username, SockAddr ip);

/* count rules in the config file */
static int number_of_rules(void);

/* load rules from the file */
static void load_rules(void);

static bool load_rule(int line, const char * dbname, const char * user, const char * ip, const char * mask, int limit);

static bool check_ip(SockAddr *raddr, struct sockaddr * addr, struct sockaddr * mask);

static bool attach_procarray(void);

static bool backend_info_is_valid(BackendInfo info, pid_t pid);
static void backend_update_info(BackendInfo * info, pid_t pid, char * database, char * role, SockAddr socket);

static bool is_super_user(char * rolename);

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
	char	dbname[NAMEDATALEN], user[NAMEDATALEN], ip[NAMEDATALEN];
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
		// FIXME handle empty lines and lines with separate netmask
		if (sscanf(line, "%s %s %s %d", dbname, user, ip, &limit) == 4) {
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
	
	elog(WARNING, "loaded %d connection limit rule(s)", rules->n_rules);

}

static
bool load_rule(int line, const char * dbname, const char * user, const char * ip, const char * mask, int limit)
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
	
	/* FIXME load the IP (see parse_hba_line in hba.c) */
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
		else if (strlen(rule->hostname) != 0)
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
	
	/* successfully parsed - increment */
	rules->n_rules += 1;
	
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
		
		int			index;
		
		elog(WARNING, "rule check start");

		/* lock ProcArray (serialize the processes) */
		LWLockAcquire(ProcArrayLock, LW_SHARED);

		/* reset the rules */
		reset_rules();
		
		/* attach the shared segment */
		attach_procarray();
		
		for (index = 0; index < procArray->numProcs; index++)
		{
		
			volatile PGPROC *proc = procArray->procs[index];
			
			if (proc->pid == 0) {
				/* do not count prepared xacts */
				continue;
			} else {
				
				/* if this is the backend, then update the local info */
				if (proc->backendId == MyBackendId) {
					backend_update_info(&backends[proc->backendId], proc->pid,
										port->database_name, port->user_name, port->raddr);
				}
				
				/* check all the rules for this backend */
				for (r = 0; r < rules->n_rules; r++) {
					
					/* the rule has to matche both the backend and the current session
					 * at the same time */
					if (rule_matches(rules->rules[r], port->database_name, port->user_name, port->raddr)) {
						
						/* check the rule for a backend - if the PID is different, the backend is
						 * waiting on the lock (and will be processed soon) */
						if (backend_info_is_valid(backends[proc->backendId], proc->pid) &&
							(rule_matches(rules->rules[r], backends[proc->backendId].database,
										  backends[proc->backendId].role, backends[proc->backendId].socket))) {
									
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
				
			}
		}

		LWLockRelease(ProcArrayLock);

	} /* (status == STATUS_OK) */

}

static
bool rule_matches(rule_t rule, const char * dbname, const char * user, SockAddr ip) {
	
	/* dbname does not match */
	if ((rule.fields & CHECK_DBNAME) && (strcmp(rule.database, dbname) != 0)) {
		return false;
	}
	
	/* username does not match */
	if ((rule.fields & CHECK_USER) && (strcmp(rule.user, user) != 0)) {
		return false;
	}
	
	// FIXME check IP
	if (rule.fields & CHECK_IP) {
		
		if (! check_ip(&ip, (struct sockaddr *)&rule.ip, (struct sockaddr *)&rule.mask)) {
			return false;
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
								 mul_size(sizeof(PGPROC *),
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
static void backend_update_info(BackendInfo * info, pid_t pid, char * database, char * role, SockAddr socket) {
	
	info->pid = pid;
	strcpy(info->database, database);
	strcpy(info->role, role);
	memcpy(&info->socket, &socket, sizeof(SockAddr));
	
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
							SnapshotNow,
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
