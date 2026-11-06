CREATE TABLE settings (
    id INTEGER PRIMARY KEY CHECK(id=1),
    revision INTEGER NOT NULL CHECK(revision>0),
    index_path TEXT NOT NULL CHECK(length(index_path) BETWEEN 1 AND 2048),
    listen TEXT NOT NULL CHECK(length(listen) BETWEEN 1 AND 64),
    upstream TEXT NOT NULL CHECK(length(upstream) BETWEEN 1 AND 64),
    categories INTEGER NOT NULL CHECK(categories BETWEEN 0 AND 127),
    max_inflight INTEGER NOT NULL CHECK(max_inflight BETWEEN 1 AND 4096),
    max_tcp_connections INTEGER NOT NULL CHECK(max_tcp_connections BETWEEN 1 AND 1024),
    cache_bytes INTEGER NOT NULL CHECK(cache_bytes=0 OR cache_bytes BETWEEN 4096 AND 16777216),
    timeout_ms INTEGER NOT NULL CHECK(timeout_ms BETWEEN 1 AND 30000)
) STRICT;
CREATE TABLE allowed_clients (
    position INTEGER PRIMARY KEY CHECK(position BETWEEN 0 AND 31),
    network TEXT NOT NULL CHECK(length(network) BETWEEN 1 AND 64)
) STRICT;
