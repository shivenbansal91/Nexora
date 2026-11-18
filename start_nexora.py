"""Local one-click startup; launched by Start Nexora.bat."""
from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
URL = 'http://127.0.0.1:8000'
# Localhost must not be sent through a configured HTTP proxy.
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get_json(path):
    try:
        with HTTP.open(URL + path, timeout=1) as response:
            return json.load(response)
    except (OSError, urllib.error.URLError, ValueError):
        return {}


def is_ready():
    return (get_json('/api').get('name') == 'Nexora Security Monitoring API'
            and get_json('/api/health').get('status') == 'ok')


def prepare_frontend():
    frontend = ROOT / 'frontend'
    index = frontend / 'dist' / 'index.html'
    inputs = [frontend / 'index.html', *frontend.glob('*.json'), *frontend.glob('*.ts'),
              *(frontend / 'src').rglob('*')]
    if index.is_file() and (frontend / 'dist' / 'assets').is_dir() and all(
        path.stat().st_mtime <= index.stat().st_mtime for path in inputs if path.is_file()
    ):
        return
    npm = shutil.which('npm.cmd' if sys.platform == 'win32' else 'npm')
    if not npm:
        raise RuntimeError('The dashboard needs building. Install Node.js, then double-click Start Nexora.bat again.')
    if not (frontend / 'node_modules').is_dir():
        raise RuntimeError('Frontend dependencies are missing. Run: npm ci --prefix frontend')
    print('Building the dashboard...', flush=True)
    subprocess.run([npm, 'run', 'build', '--prefix', str(frontend)], cwd=ROOT, check=True)


def wait_until_ready(process, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('The server stopped during startup. Check the error above; install Python dependencies with: python -m pip install -r requirements.txt')
        if is_ready():
            return
        time.sleep(.3)
    raise RuntimeError('The server did not become healthy within 60 seconds. Check its startup messages above.')


def main():
    process = None
    try:
        prepare_frontend()
        if is_ready():
            print('Nexora is already running. Opening the dashboard.', flush=True)
            webbrowser.open(URL + '/dashboard')
            return 0
        # Never stop or reuse an unrelated service occupying the port.
        with socket.socket() as probe:
            try:
                probe.bind(('127.0.0.1', 8000))
            except OSError as error:
                raise RuntimeError('Port 8000 is in use, but a healthy Nexora server was not found. Close the conflicting server and try again.') from error
        print('Starting Nexora. Keep this window open. Press Ctrl+C to stop.', flush=True)
        process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'backend.app.main:app',
                                    '--host', '127.0.0.1', '--port', '8000'], cwd=ROOT)
        wait_until_ready(process)
        print(f'Dashboard: {URL}/dashboard', flush=True)
        if not webbrowser.open(URL + '/dashboard'):
            print('Open the dashboard address above in your browser.', flush=True)
        return process.wait()
    except KeyboardInterrupt:
        print('\nStopping Nexora...', flush=True)
        return 0
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f'\n{error}', file=sys.stderr)
        return 1
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    raise SystemExit(main())
