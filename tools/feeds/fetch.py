"""Fetch selected public feed sources into a bounded, ignored development cache.

This is on-demand development tooling, not the service's future refresh scheduler.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request


def validate_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or len(url) > 2048):
        raise ValueError('feed URLs must be HTTPS URLs without credentials')
    return url


class HTTPSRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        validate_url(new_url)
        return super().redirect_request(request, fp, code, message, headers, new_url)


def fetch_source(source, cache, max_bytes, opener=None, max_cache_bytes=8_000_000):
    identifier = source['id']
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', identifier):
        raise ValueError('invalid source identifier')
    url = validate_url(source['url'])
    if max_bytes <= 0 or max_cache_bytes <= 0:
        raise ValueError('byte limits must be positive')
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    used = sum(p.stat().st_size for p in cache.rglob('*') if p.is_file())
    # Reserve metadata staging space as well as the old data and new download.
    available = min(max_bytes, max_cache_bytes - used - 4096)
    if available <= 0:
        raise ValueError('insufficient cache space for a staged refresh')
    part = cache / (identifier + '.part')
    metadata_part = cache / (identifier + '.metadata.part')
    created = metadata_created = False
    if opener is None:
        handler = urllib.request.build_opener(HTTPSRedirects())
        opener = lambda request: handler.open(request, timeout=30)
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'dns-guard-feed-fetcher/0.1'})
        digest = hashlib.sha256()
        size = 0
        with part.open('xb') as output:
            created = True
            with opener(request) as response:
                if getattr(response, 'status', 200) != 200:
                    raise ValueError('unexpected feed HTTP status')
                while chunk := response.read(65536):
                    size += len(chunk)
                    if size > available:
                        raise ValueError('feed exceeds download or staged cache budget')
                    output.write(chunk)
                    digest.update(chunk)
            if size == 0:
                raise ValueError('empty feed response')
            output.flush()
            os.fsync(output.fileno())
        metadata = {'id': identifier, 'url': url, 'format': source.get('format'),
                    'sha256': digest.hexdigest(), 'bytes': size,
                    'fetched_at': datetime.now(timezone.utc).isoformat()}
        encoded = (json.dumps(metadata, indent=2) + '\n').encode()
        if len(encoded) > 4096:
            raise ValueError('source metadata exceeds reserved space')
        with metadata_part.open('xb') as output:
            metadata_created = True
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(part, cache / (identifier + '.txt'))
        os.replace(metadata_part, cache / (identifier + '.json'))
        return metadata
    finally:
        if created:
            part.unlink(missing_ok=True)
        if metadata_created:
            metadata_part.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, default=Path(__file__).resolve().parents[2] / 'config/sources.json')
    parser.add_argument('--cache', type=Path, default=Path('.cache/feeds'))
    parser.add_argument('--source', action='append', default=[])
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--max-bytes', type=int, default=4_000_000)
    parser.add_argument('--max-cache-bytes', type=int, default=8_000_000)
    args = parser.parse_args()
    sources = json.loads(args.catalog.read_text())['sources']
    catalog = {source['id']: source for source in sources}
    if len(catalog) != len(sources):
        parser.error('catalog contains duplicate source identifiers')
    if args.list:
        print(json.dumps(sources, indent=2))
        return
    if not args.source:
        parser.error('select at least one --source, or use --list')
    if any(identifier not in catalog for identifier in args.source):
        parser.error('unknown source identifier')
    for identifier in dict.fromkeys(args.source):
        result = fetch_source(catalog[identifier], args.cache, args.max_bytes,
                              max_cache_bytes=args.max_cache_bytes)
        print(json.dumps(result))


if __name__ == '__main__':
    main()
