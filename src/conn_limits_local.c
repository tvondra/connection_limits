#include <sys/ipc.h>

#include "postgres.h"

#include "executor/executor.h"
#include "executor/instrument.h"

#include "conn_limits.h"

/* segment with rules */
static rules_t * rules = NULL;

void		_PG_init(void);

/*
 * Module load callback
 */
void
_PG_init(void)
{
	
	bool	found = FALSE;
	char   *segment = NULL;
	
	/* can be preloaded only from postgresql.conf */
	if (process_shared_preload_libraries_in_progress)
		elog(ERROR, "conn_limits_local should be loaded using "
					"local_preload_libraries");
	
	segment = ShmemInitStruct(SEGMENT_NAME, SEGMENT_SIZE, &found);

	if (! found) {
		elog(WARNING, "segment with connection rules not found (is the "
					"connection_limits_shared lib loaded?)");
		return;
	}

	/* set the pointers */
	rules = (rules_t*)(segment);
	
	if ((rules->fail) && (! superuser())) {
		elog(ERROR, "connection limit reached");
	} else if (rules->fail) {
		elog(WARNING, "connection limit reached, but the user is a superuser");
	}
	
	// unlock
	LWLockRelease(rules->lock);
	
}
