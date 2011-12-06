CREATE OR REPLACE FUNCTION connection_limits(OUT line INT, OUT database VARCHAR, OUT username VARCHAR, OUT ip_or_hostname VARCHAR, OUT count INT, OUT max_count INT)
    RETURNS SETOF record
    AS 'MODULE_PATHNAME', 'connection_limits'
    LANGUAGE C IMMUTABLE;
