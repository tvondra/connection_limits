#include "postgres.h"
#include "miscadmin.h"
#include "storage/ipc.h"
#include "storage/fd.h"
#include "storage/proc.h"
#include "storage/s_lock.h"
#include "libpq/pqcomm.h"

#include "pg_config_manual.h"

#define LIMITS_FILE	 "pg_limits.conf"
#define SEGMENT_NAME	"connection_limits"

/* by default space for 1000 rules */
#define MAX_RULES		1000
#define SEGMENT_SIZE	(sizeof(rule_t) * (MAX_RULES-1) + sizeof(rules_t) + sizeof(BackendInfo) * MaxBackends)
#define PROCARRAY_MAXPROCS	(MaxBackends + max_prepared_xacts)

#define LINE_MAXLEN	 1024

#define CHECK_DBNAME	1
#define CHECK_USER		2
#define CHECK_IP		4
#define CHECK_HOST		8

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

typedef struct rule_t {
	
	/* line number (for messages) */
	int line;
	
	/* which fields to use */
	int fields;
	
	/* database OID */
	char database[NAMEDATALEN];
	
	/* user name */
	char user[NAMEDATALEN];
	
	/* hostname */
	char hostname[NAMEDATALEN];
	
	/* IP address and mask */
	struct sockaddr_storage ip;
	struct sockaddr_storage mask;

	/* current counter */
	int count;
	
	/* max number of connections */
	int limit;
	
} rule_t;

typedef struct rules_t {
	
	int n_rules;
	
	rule_t rules[1];
	
} rules_t;

/* Our shared memory area */
typedef struct ProcArrayStruct
{
	int			numProcs;		/* number of valid procs entries */
	int			maxProcs;		/* allocated size of procs array */

	/*
	 * Known assigned XIDs handling
	 */
	int			maxKnownAssignedXids;	/* allocated size of array */
	int			numKnownAssignedXids;	/* currrent # of valid entries */
	int			tailKnownAssignedXids;	/* index of oldest valid element */
	int			headKnownAssignedXids;	/* index of newest element, + 1 */
	slock_t		known_assigned_xids_lck;		/* protects head/tail pointers */

	/*
	 * Highest subxid that has been removed from KnownAssignedXids array to
	 * prevent overflow; or InvalidTransactionId if none.  We track this for
	 * similar reasons to tracking overflowing cached subxids in PGPROC
	 * entries.  Must hold exclusive ProcArrayLock to change this, and shared
	 * lock to read it.
	 */
	TransactionId lastOverflowedXid;

#if (PG_VERSION_NUM >= 90400)
	/* oldest xmin of any replication slot */
	TransactionId replication_slot_xmin;
	/* oldest catalog xmin of any replication slot */
	TransactionId replication_slot_catalog_xmin;
#endif

	/*
	 * We declare procs[] as 1 entry because C wants a fixed-size array, but
	 * actually it is maxProcs entries long.
	 */
#if (PG_VERSION_NUM <= 90200)
	PGPROC	   *procs[1];		/* VARIABLE LENGTH ARRAY */
#else
	int			procs[1];		/* VARIABLE LENGTH ARRAY */
#endif
	
} ProcArrayStruct;

typedef struct BackendInfo {

	int			pid;
	char		database[NAMEDATALEN];
	char		role[NAMEDATALEN];
	SockAddr 	socket;
	char		hostname[NAMEDATALEN];

} BackendInfo;
