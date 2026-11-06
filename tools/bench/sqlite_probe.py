#!/usr/bin/env python3
"""Standalone SQLite experiment; not a production history store.

Compare identical FULL-durability WAL commits at batch sizes 1 and 256. Keep the
connection and prepared SQL stable, and include checkpoint costs in write time.
File sizes are sampled after each commit, not a strict peak allocation bound.
"""
import argparse
import json
import math
import pathlib
import sqlite3
import statistics
import subprocess
import tempfile
import time

ROWS = 8192
SQL = 'INSERT INTO events VALUES (?, ?, ?, ?, ?)'
SELECT = 'SELECT ts, id, blocked FROM events WHERE client = ? AND ts >= ? ORDER BY ts, id LIMIT 100'


def probe(batch, directory):
    with tempfile.TemporaryDirectory(prefix='dns-sqlite-probe-', dir=directory) as directory:
        path = pathlib.Path(directory) / 'history.sqlite'
        db = sqlite3.connect(path)
        assert db.execute('PRAGMA journal_mode=WAL').fetchone()[0] == 'wal'
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA cache_size=-256')
        db.execute('PRAGMA wal_autocheckpoint=64')
        db.execute('CREATE TABLE events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, client INTEGER NOT NULL, domain INTEGER NOT NULL, blocked INTEGER NOT NULL)')
        db.commit()
        data = [(i, 1700000000 + i // 32, i % 64, i % 2000, i % 3 == 0) for i in range(ROWS)]
        durations = []
        peak_files = 0
        started = time.perf_counter()
        for offset in range(0, ROWS, batch):
            tick = time.perf_counter_ns()
            with db:
                db.executemany(SQL, data[offset:offset + batch])
            durations.append(time.perf_counter_ns() - tick)
            peak_files = max(peak_files, sum(p.stat().st_size for p in pathlib.Path(directory).iterdir()))
        checkpoint = db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
        elapsed = time.perf_counter() - started
        assert checkpoint[0] == 0
        assert db.execute('SELECT COUNT(*), SUM(blocked) FROM events').fetchone() == (ROWS, sum(row[4] for row in data))
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        params = (17, 1700000000)
        expected = db.execute(SELECT, params).fetchall()
        plans = {}
        reads = {}
        sizes = {'without_index': path.stat().st_size}
        for indexed in [False, True]:
            label = 'covering' if indexed else 'scan'
            if indexed:
                db.execute('CREATE INDEX client_recent ON events(client, ts, id, blocked)')
                db.commit()
                db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                sizes['with_covering_index'] = path.stat().st_size
            plans[label] = [row[3] for row in db.execute('EXPLAIN QUERY PLAN ' + SELECT, params)]
            samples = []
            for _ in range(200):
                tick = time.perf_counter_ns()
                result = db.execute(SELECT, params).fetchall()
                samples.append(time.perf_counter_ns() - tick)
                assert result == expected
            samples.sort()
            reads[label] = dict(p50_us=statistics.median(samples) / 1000, p99_us=samples[math.ceil(len(samples) * .99) - 1] / 1000)
        db.close()
        durations.sort()
        return dict(batch=batch, rows=ROWS, seconds=elapsed, rows_per_s=ROWS / elapsed,
                    commits=len(durations), commit_p99_ms=durations[math.ceil(len(durations) * .99) - 1] / 1e6,
                    sampled_peak_files_bytes=peak_files, file_bytes=sizes, plans=plans, reads=reads)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', default='.', help='parent directory on the filesystem to measure')
    args = parser.parse_args()
    filesystem = subprocess.check_output(['findmnt', '-T', args.directory, '-no', 'FSTYPE'], text=True).strip()
    print(json.dumps(dict(sqlite_version=sqlite3.sqlite_version, storage=dict(directory=str(pathlib.Path(args.directory).resolve()), filesystem=filesystem),
                         settings=dict(synchronous='FULL', cache_kib=256, checkpoint_pages=64),
                         runs=[probe(batch, args.directory) for batch in [1, 256, 256, 1]]), indent=2))
