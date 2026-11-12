"""Supervise the TanStack Start web boundary; settlement and key custody stay private."""

import hashlib
import http.client
import os
from pathlib import Path
import shutil
from urllib.parse import urlsplit

from .runtime import load_config, read_ready_line, save_config

UI = Path(__file__).with_name('ui')


def launch_web(directory, processes, engine_url, token, port):
    directory = Path(directory)
    config_path = directory / 'start-web.json'
    previous = load_config(config_path) if config_path.exists() else {}
    executable = os.environ.get('ELEMENTS_UI_NODE') or previous.get('node_executable') or shutil.which('node')
    if not executable or not Path(executable).is_file():
        raise RuntimeError('Node.js is required for TanStack Start; set ELEMENTS_UI_NODE to its executable')
    if not (UI / 'dist/server/server.js').is_file():
        raise RuntimeError('build the TanStack Start UI first: cd contrib/threshold-audit/settlement/ui && npm ci && npm run build')
    # Each running server keeps its own immutable asset/manifest pair while a
    # later build replaces dist. Dependencies remain in the UI's node_modules.
    digest = hashlib.sha256()
    for artifact in sorted((UI / 'dist').rglob('*')):
        if artifact.is_file():
            digest.update(artifact.relative_to(UI / 'dist').as_posix().encode())
            digest.update(artifact.read_bytes())
    release = UI / '.releases' / digest.hexdigest()
    if not release.exists():
        release.parent.mkdir(exist_ok=True)
        temporary = release.with_name(release.name + '.next-' + str(os.getpid()))
        shutil.copytree(UI / 'dist', temporary)
        try:
            temporary.rename(release)
        except FileExistsError:
            shutil.rmtree(temporary)
    config = {'engine_url': engine_url, 'token': token, 'port': port,
              'build_dir': str(release),
              'node_executable': str(Path(executable).resolve())}
    save_config(config_path, config)
    process = processes.spawn([config['node_executable'], str(UI / 'scripts/serve.mjs'), '--config', str(config_path)],
                              directory / 'start-web.log', readiness=True)
    ready = read_ready_line(process, timeout=30)
    expected = f'http://127.0.0.1:{port}/'
    if ready.get('url') != expected or ready.get('pid') != process.pid or ready.get('backend') != 'tanstack-start':
        raise RuntimeError('invalid TanStack Start readiness response')
    # Readiness covers both the web listener and the authenticated engine bridge.
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
    try:
        connection.request('GET', '/api/session')
        response = connection.getresponse()
        response.read()
        if response.status != 200:
            raise RuntimeError('TanStack Start cannot reach the private settlement engine')
    finally:
        connection.close()
    return process, expected
