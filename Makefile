OBJS = src/conn_limits_local.o src/conn_limits_shared.o

EXTENSION = connection_limits
DATA = sql/connection_limits--1.0.0.sql
MODULES = connection_limits_local connection_limits_shared

CFLAGS=`pg_config --includedir-server`

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

all: connection_limits_shared.so connection_limits_local.so

connection_limits_local.so: src/conn_limits_local.o
	${CC} ${CFLAGS} ${LDFLAGS} -shared -o connection_limits_local.so src/conn_limits_local.o

connection_limits_shared.so: src/conn_limits_shared.o
	${CC} ${CFLAGS} ${LDFLAGS} -shared -o connection_limits_shared.so src/conn_limits_shared.o

src/%.o : src/%.c