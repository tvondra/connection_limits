CREATE OR REPLACE FUNCTION connection_limits(OUT line INT, OUT database VARCHAR, OUT username VARCHAR, OUT ip_or_hostname VARCHAR, OUT count INT, OUT max_count INT)
    RETURNS SETOF record
    AS 'MODULE_PATHNAME', 'connection_limits'
    LANGUAGE C IMMUTABLE;

CREATE VIEW connection_limits AS SELECT * FROM connection_limits();

CREATE OR REPLACE FUNCTION connection_limits_reload()
    RETURNS void
    AS 'MODULE_PATHNAME', 'connection_reload_config'
    LANGUAGE C;
