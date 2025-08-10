MODULE_big = jwt_context
OBJS = jwt_context.o jwt_hs256.o jwt_es256.o jwt_base64.o

EXTENSION = jwt_context
DATA = sql/jwt_context--1.0.0.sql
MODULES = jwt_context

CFLAGS=`pg_config --includedir-server`

TESTS        = $(wildcard test/sql/*.sql)
REGRESS      = $(patsubst test/sql/%.sql,%,$(TESTS))
REGRESS_OPTS = --inputdir=test

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

SHLIB_LINK += -lcrypto
