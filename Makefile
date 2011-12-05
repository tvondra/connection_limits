OBJS = src/connection_limits.o

EXTENSION = connection_limits
DATA = sql/connection_limits--1.0.0.sql
MODULES = connection_limits

CFLAGS=`pg_config --includedir-server`

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

all: connection_limits.so

connection_limits.so: src/connection_limits.o
	${CC} ${CFLAGS} ${LDFLAGS} -shared -o connection_limits.so src/connection_limits.o

src/%.o : src/%.c