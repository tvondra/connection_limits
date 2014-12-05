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
#define RULES_SEGMENT_SIZE		(offsetof(rules_t, rules) + sizeof(rule_t) * MAX_RULES)
#define BACKENDS_SEGMENT_SIZE	(sizeof(BackendInfo) * MaxBackends)
#define SEGMENT_SIZE			(RULES_SEGMENT_SIZE + BACKENDS_SEGMENT_SIZE)
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

	/* line number (used for error messages) */
	int line;

	/* which fields to use */
	int fields;

	/* database name */
	char database[NAMEDATALEN];

	/* user name */
	char user[NAMEDATALEN];

	/* hostname (can't be used together with IP adress) */
	char hostname[NAMEDATALEN];

	/* IP address and mask (can't be used together with hostname) */
	struct sockaddr_storage ip;
	struct sockaddr_storage mask;

	/* current counter status */
	int count;

	/* max number of connections */
	int limit;

} rule_t;

typedef struct rules_t {

	/* current number of rules */
	int n_rules;

	/* rules (up to MAX_RULES) */
	rule_t rules[1];	/* variable-length array */

} rules_t;

/* Our shared memory area (copy of private struct from storage/ipc/procarray.c)
 *
 * TODO Maybe this should be private to connection_limits.c (just like the
 *      original structure).
 */
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

/* cached info about a backend (database name, etc.) */
typedef struct BackendInfo {

	int			pid;

	BackendId	backendId;

	char		database[NAMEDATALEN];
	char		role[NAMEDATALEN];
	char		hostname[NAMEDATALEN];

	SockAddr 	socket;

} BackendInfo;
