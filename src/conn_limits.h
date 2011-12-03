#define LIMITS_FILE	 "pg_limits.conf"
#define SEGMENT_NAME	"connection_limits"

/* by default space for 1000 rules */
#define MAX_RULES	   1000
#define SEGMENT_SIZE	(sizeof(rule_t) * (MAX_RULES-1) + sizeof(rules_t))

#define NAME_MAXLEN	 64
#define LINE_MAXLEN	 256

#include "postgres.h"
#include "miscadmin.h"
#include "storage/ipc.h"
#include "storage/fd.h"

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
	char database[NAME_MAXLEN];
	
	/* user name */
	char user[NAME_MAXLEN];
	
	/* hostname */
	char hostname[NAME_MAXLEN];
	
	/* IP address and mask */
	struct sockaddr_storage ip;
	struct sockaddr_storage mask;

	/* current counter */
	int count;
	
	/* max number of connections */
	int limit;
	
} rule_t;

typedef struct rules_t {
	
	LWLockId lock;
	
	int n_rules;
	
	bool fail;
	
	rule_t rules[1];
	
} rules_t;