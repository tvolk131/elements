"""Local fixture file formats and bounded, owned subprocess lifecycle.

This module owns no cryptographic or settlement policy. Runtime manifests
contain private fixture credentials and must never be included in review bundles.
"""

import json
import os
from pathlib import Path
import selectors
import stat
import subprocess
import threading
import time

from guardian_service import atomic_write

SCHEMA_VERSION = 1
MAX_STARTUP_BYTES = 65536


def load_config(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError(f'private runtime file must be regular and mode 0600: {path.name}')
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f'expected runtime object: {path.name}')
    version = value.get('schema_version', SCHEMA_VERSION)
    if type(version) is not int or version != SCHEMA_VERSION:
        raise ValueError(f'unsupported runtime schema in {path.name}')
    return value


def save_config(path, value):
    if not isinstance(value, dict):
        raise ValueError('versioned runtime configuration must be an object')
    atomic_write(path, dict(value, schema_version=SCHEMA_VERSION))


def read_ready_line(process, *, timeout=30, maximum=MAX_STARTUP_BYTES):
    """A single bounded monotonic deadline includes partial readiness lines."""
    if process.stdout is None:
        raise ValueError('readiness process has no stdout pipe')
    selector, output = selectors.DefaultSelector(), bytearray()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    try:
        while b'\n' not in output:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise RuntimeError('service readiness deadline exceeded')
            chunk = os.read(process.stdout.fileno(), min(4096, maximum + 1 - len(output)))
            if not chunk:
                raise RuntimeError('service exited before publishing readiness')
            output.extend(chunk)
            if len(output) > maximum:
                raise RuntimeError('service readiness exceeds size bound')
        result = json.loads(bytes(output).split(b'\n', 1)[0])
        if not isinstance(result, dict):
            raise ValueError('service readiness must be an object')
        return result
    finally:
        selector.close()


class OwnedProcesses:
    """Manage only Popen handles created by this launcher, including failures."""
    def __init__(self, directory=None):
        self.children, self.logs = [], []
        self.directory = None if directory is None else Path(directory)
        self.labels = {}
        self.identities = {}
        self.lock = threading.RLock()
        self.closing = False

    def _save_registry(self):
        if self.directory is None:
            return
        entries = []
        for process in self.children:
            entries.append({'pid': process.pid, 'start_ticks': self.identities[process.pid],
                            'label': self.labels[process.pid], 'running': process.poll() is None})
        save_config(self.directory / 'processes.json', {'owner_pid': os.getpid(), 'processes': entries})

    def spawn(self, command, log_path, *, readiness=False):
        with self.lock:
            if self.closing:
                raise RuntimeError('owned process launcher is shutting down')
            return self._spawn(command, log_path, readiness=readiness)

    def _spawn(self, command, log_path, *, readiness=False):
        path = Path(log_path)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.fchmod(descriptor, 0o600)
        log = os.fdopen(descriptor, 'ab')
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE if readiness else log,
                                       stderr=log, start_new_session=True)
        except BaseException:
            log.close()
            raise
        self.children.append(process)
        self.logs.append(log)
        self.labels[process.pid] = path.relative_to(self.directory).as_posix() if self.directory else path.name
        try:
            fields = Path(f'/proc/{process.pid}/stat').read_text().rsplit(')', 1)[1].split()
            self.identities[process.pid] = int(fields[19])
        except (OSError, ValueError, IndexError):
            self.identities[process.pid] = None
        self._save_registry()
        return process

    @staticmethod
    def stop(process, timeout=10):
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        if process.stdout is not None:
            process.stdout.close()

    def close(self):
        with self.lock:
            self.closing = True
            for process in reversed(self.children):
                self.stop(process)
            for log in self.logs:
                log.close()
            self._save_registry()
