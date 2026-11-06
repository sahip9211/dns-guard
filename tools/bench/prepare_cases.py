#!/usr/bin/env python3
"""Build shared direct/k6 queries and an independent suffix oracle from two feeds.

Usage: python3 -m tools.bench.prepare_cases OUTPUT_DIR ADS_ADBLOCK ADULT_ADBLOCK
The ads category here is an assigned test mask, not a classification of the feed.
"""
import hashlib
import json
import pathlib
import sys


def main():
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    output = pathlib.Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    blocks, allows, sources = {}, {}, []
    for category, filename in zip((1, 2), sys.argv[2:]):
        raw = pathlib.Path(filename).read_bytes()
        count = 0
        for raw_line in raw.decode('utf-8').splitlines():
            line = raw_line.strip()
            if not line or line.startswith('!') or line in ('[Adblock Plus]', '[Adblock Plus 2.0]'):
                continue
            target = blocks
            if line.startswith('@@'):
                target, line = allows, line[2:]
            if not line.startswith('||') or not line.endswith('^'):
                raise ValueError(f'unsupported rule: {line}')
            domain = line[2:-1].removesuffix('.').lower()
            if not domain.isascii() or not all(0 < len(label) <= 63 and label[0].isalnum() and label[-1].isalnum() and all(c.isalnum() or c == '-' for c in label) for label in domain.split('.')):
                raise ValueError(f'invalid hostname: {domain}')
            target[domain] = target.get(domain, 0) | category
            count += 1
        sources.append({'path': filename, 'sha256': hashlib.sha256(raw).hexdigest(), 'rules': count})

    def expected(domain, enabled):
        labels = domain.removesuffix('.').lower().split('.')
        block = allow = 0
        for i in range(len(labels)):
            suffix = '.'.join(labels[i:])
            block |= blocks.get(suffix, 0)
            allow |= allows.get(suffix, 0)
        return (block & ~allow) & enabled

    domains = sorted(blocks)
    stride = max(1, len(domains) // 3000)
    queries = []
    for n, domain in enumerate(domains[::stride][:3000]):
        candidates = [(domain, 127), (domain.upper() + '.', 1), (f'negative-{n}.invalid', 127)]
        if len(domain) <= 247:
            candidates.append(('probe.' + domain, 2))
        for query, mask in candidates:
            queries.append({'domain': query, 'categories': mask, 'blocked': expected(query, mask)})
    (output / 'queries.tsv').write_text(''.join(f"{q['domain']}\t{q['categories']}\t{q['blocked']}\n" for q in queries))
    (output / 'cases.json').write_text(json.dumps(queries, separators=(',', ':')) + '\n')
    (output / 'sources.json').write_text(json.dumps({'sources': sources, 'queries': len(queries)}, indent=2) + '\n')
    print(f'Wrote {len(queries)} queries for {len(domains)} distinct blocking domains')


if __name__ == '__main__':
    main()
