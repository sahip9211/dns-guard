"""Run the native library test against a disposable Secret Service session.

Requires dbus-run-session and gnome-keyring-daemon. Does not unlock or modify the
desktop user's existing keyring. Test fixtures are removed when the session ends.
"""
import os
import pathlib
import subprocess
import tempfile


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='dns-keyring-session-') as directory:
        root = pathlib.Path(directory)
        env = os.environ.copy()
        for variable, folder in [('XDG_DATA_HOME', 'data'), ('XDG_CONFIG_HOME', 'config'),
                                 ('XDG_CACHE_HOME', 'cache'), ('XDG_RUNTIME_DIR', 'runtime')]:
            path = root / folder
            path.mkdir(mode=0o700)
            env[variable] = str(path)
        env.pop('DISPLAY', None)
        env.pop('WAYLAND_DISPLAY', None)
        script = '''
set -eu
printf '%s' 'synthetic-ci-keyring-only' | gnome-keyring-daemon --unlock --components=secrets >/dev/null
exec cargo test --test keyring_native --locked -- --ignored --nocapture
'''
        result = subprocess.run(['dbus-run-session', '--', 'sh', '-c', script], env=env,
                                cwd=pathlib.Path(__file__).resolve().parents[2], timeout=180)
        raise SystemExit(result.returncode)
