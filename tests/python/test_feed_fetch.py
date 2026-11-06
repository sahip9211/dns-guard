import io
import tempfile
import unittest
from pathlib import Path
from tools.feeds.fetch import fetch_source, validate_url


class Response(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *args): self.close()


class FeedFetchTests(unittest.TestCase):
    def test_download_records_hash_and_replaces_only_complete_files(self):
        with tempfile.TemporaryDirectory() as directory:
            source = {'id': 'test-feed', 'url': 'https://example.org/list.txt', 'format': 'adblock'}
            metadata = fetch_source(source, Path(directory), 1024, lambda request: Response(b'||ads.example^\n'))
            self.assertEqual(metadata['bytes'], 15)
            self.assertEqual(len(metadata['sha256']), 64)
            self.assertEqual((Path(directory) / 'test-feed.txt').read_bytes(), b'||ads.example^\n')
            with self.assertRaises(ValueError):
                fetch_source(source, Path(directory), 2, lambda request: Response(b'too large'))
            self.assertEqual((Path(directory) / 'test-feed.txt').read_bytes(), b'||ads.example^\n')
            self.assertFalse(list(Path(directory).glob('*.part')))

    def test_urls_and_ids_cannot_escape_the_cache_or_downgrade_transport(self):
        for url in ['http://example.org/a', 'file:///etc/hosts', 'https://u:p@example.org/a', 'https:///a']:
            with self.assertRaises(ValueError): validate_url(url)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                fetch_source({'id': '../escape', 'url': 'https://example.org/a'}, Path(directory), 1024, lambda request: Response(b'x'))

    def test_interrupted_download_leaves_previous_feed_intact(self):
        class Broken(Response):
            def read(self, size=-1): raise OSError('interrupted')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test.txt'; path.write_bytes(b'old')
            with self.assertRaises(OSError):
                fetch_source({'id': 'test', 'url': 'https://example.org/a'}, Path(directory), 1024, lambda request: Broken())
            self.assertEqual(path.read_bytes(), b'old')
            self.assertFalse(list(Path(directory).glob('*.part')))
