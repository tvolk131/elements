#!/usr/bin/env python3
"""Build and verify the experimental fork with private, owned test runtimes.

Quick: public vectors, Python tests, selected native tests and review-patch apply.
Full: quick plus native functional regressions and restarted A->B->C settlement.
The JSON report distinguishes completed checks from explicit skips. No real bank
or external service is contacted. Logs/runtime keys remain in the private run dir.
"""

import argparse
import configparser
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from export_review import ROOT, category, git


def utc():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path, value):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class VerificationFailure(RuntimeError):
    def __init__(self, message, exit_code=1):
        super().__init__(message)
        self.exit_code = exit_code


class Interrupted(VerificationFailure):
    pass


class OwnedProcess:
    """One newly created process session, never a PID discovered by name."""
    def __init__(self, command, log, *, cwd=ROOT, env=None):
        self.command, self.log = list(map(str, command)), Path(log)
        self.stream = self.log.open('ab')
        os.chmod(self.log, 0o600)
        self.process = subprocess.Popen(self.command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                        stdout=self.stream, stderr=subprocess.STDOUT, start_new_session=True)
        self.identity = process_identity(self.process.pid)
        self.runtime = None
        self.closed = False

    def stop(self, timeout=25):
        if self.closed:
            return
        owned = descendant_snapshot(self.process.pid, self.identity)
        owned.update(session_snapshot(self.process.pid, self.identity))
        if self.runtime is not None:
            owned.update(runtime_snapshot(self.runtime, self.identity))
        try:
            if self.process.poll() is None:
                self.process.send_signal(signal.SIGTERM)
                try:
                    self.process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    pass
            # Native daemon/institution launchers may create their own sessions.
            # Capture the descendant identities before stopping the parent, then
            # use the fresh private runtime to recover recorded orphan handles.
            if self.runtime is not None:
                owned.update(runtime_snapshot(self.runtime, self.identity))
            for pid, identity in list(owned.items()):
                if process_identity(pid) == identity:
                    owned.update(descendant_snapshot(pid, identity))
            for pid, identity in owned.items():
                signal_identity(pid, identity, signal.SIGTERM)
            if self.process.poll() is None:
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
            for pid, identity in owned.items():
                signal_identity(pid, identity, signal.SIGKILL)
            if not Path('/proc').is_dir():
                # Quick-only portability fallback; full orphan-aware lifecycle
                # verification explicitly requires Linux procfs below.
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if self.process.poll() is None:
                self.process.wait(timeout=5)
            if self.runtime is not None:
                deadline = time.monotonic() + 5
                while True:
                    survivors = runtime_snapshot(self.runtime, self.identity)
                    if not survivors:
                        break
                    for pid, identity in survivors.items():
                        signal_identity(pid, identity, signal.SIGKILL)
                    if time.monotonic() >= deadline:
                        raise RuntimeError('owned runtime server cleanup failed: ' + ','.join(map(str, survivors)))
                    time.sleep(.05)
            self.closed = True
        finally:
            self.stream.close()


def process_identity(pid):
    try:
        fields = (Path('/proc') / str(pid) / 'stat').read_text().rpartition(')')[2].split()
        return int(fields[19])
    except (OSError, ValueError, IndexError):
        return None


def descendant_snapshot(parent_pid, parent_identity):
    if parent_identity is None or process_identity(parent_pid) != parent_identity:
        return {}
    processes = {}
    for directory in Path('/proc').iterdir():
        if not directory.name.isdigit():
            continue
        try:
            fields = (directory / 'stat').read_text().rpartition(')')[2].split()
            processes[int(directory.name)] = (int(fields[1]), int(fields[19]))
        except (OSError, ValueError, IndexError):
            continue
    found = {parent_pid: parent_identity}
    while True:
        children = {pid: identity for pid, (parent, identity) in processes.items() if parent in found and pid not in found}
        if not children:
            return found
        found.update(children)


def session_snapshot(session, minimum_identity):
    if minimum_identity is None or not Path('/proc').is_dir():
        return {}
    leader = process_identity(session)
    if leader is not None and leader != minimum_identity:
        return {}  # A reused leader PID is never authority to signal a session.
    found = {}
    for directory in Path('/proc').iterdir():
        if not directory.name.isdigit():
            continue
        try:
            fields = (directory / 'stat').read_text().rpartition(')')[2].split()
            if int(fields[3]) == session and int(fields[19]) >= minimum_identity and fields[0] != 'Z':
                found[int(directory.name)] = int(fields[19])
        except (OSError, ValueError, IndexError):
            continue
    return found


def runtime_snapshot(runtime, minimum_identity):
    """Recover only known server roles using this run's fresh private runtime.

    This covers the Popen->registry crash window without scanning/killing by a
    global process name. Baseline servers point at other directories and cannot
    match. Start ticks prevent accepting an older process or a reused PID.
    """
    if minimum_identity is None or not Path('/proc').is_dir():
        return {}
    root = str(Path(runtime).resolve()) + os.sep
    found = {}
    for directory in Path('/proc').iterdir():
        if not directory.name.isdigit():
            continue
        pid = int(directory.name)
        identity = process_identity(pid)
        if identity is None or identity < minimum_identity:
            continue
        try:
            arguments = (directory / 'cmdline').read_bytes().split(b'\0')
        except OSError:
            continue
        role = (b'settlement.treasury' in arguments or b'settlement.sandbox' in arguments
                or any(argument.endswith(b'/guardian_service.py') for argument in arguments)
                or any(argument.endswith(b'/elementsd') for argument in arguments))
        paths = [argument.decode(errors='replace').split('=', 1)[-1] for argument in arguments]
        if role and any(path.startswith(root) for path in paths):
            found[pid] = identity
    return found


def signal_identity(pid, identity, number):
    if identity is None or process_identity(pid) != identity:
        return
    descriptor = None
    try:
        if hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'):
            descriptor = os.pidfd_open(pid)
            if process_identity(pid) == identity:
                signal.pidfd_send_signal(descriptor, number)
        elif process_identity(pid) == identity:
            os.kill(pid, number)
    except ProcessLookupError:
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)


def source_inventory(root=ROOT):
    tracked = git('ls-files', '-z', root=root).stdout
    other = git('ls-files', '--others', '--exclude-standard', '-z', root=root).stdout
    paths = sorted({item.decode() for item in (tracked + other).split(b'\0') if item and category(item.decode()) is not None})
    files = []
    for relative in paths:
        path = root / relative
        if path.is_symlink():
            raise VerificationFailure('review source is a symlink: ' + relative)
        if path.is_file():
            data = path.read_bytes()
            files.append({'path': relative, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)})
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'sha256': digest, 'files': files}


class Verifier:
    def __init__(self, options):
        self.options = options
        self.root = ROOT
        if options.work_dir is None:
            self.directory = Path(tempfile.mkdtemp(prefix='elements-threshold-verify-')).resolve()
        else:
            self.directory = options.work_dir.resolve()
            if self.directory.exists() and any(self.directory.iterdir()):
                raise VerificationFailure('--work-dir must be new or empty; previous keys/reports are never overwritten')
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self.logs = self.directory / 'logs'; self.logs.mkdir(mode=0o700)
        self.runtimes = self.directory / 'runtimes'; self.runtimes.mkdir(mode=0o700)
        self.temporary = self.runtimes / 'temporary'; self.temporary.mkdir(mode=0o700)
        self.native = (options.native_build or self.directory / 'build' / 'native').resolve()
        self.secp = (options.secp_build or self.directory / 'build' / 'secp256k1').resolve()
        self.library = options.library.resolve() if options.library else None
        self.processes, self.sandbox = [], None
        self.cleaning = False
        self.report_path = self.directory / 'report.json'
        self.env = dict(os.environ)
        self.env['TMPDIR'] = str(self.temporary)
        self.env['PYTHONPATH'] = os.pathsep.join([str(ROOT / 'contrib' / 'threshold-audit'),
                                               str(ROOT / 'test' / 'functional'), self.env.get('PYTHONPATH', '')])
        self.report = {'format': 'elements-threshold-audit-verification-v1', 'status': 'running',
                       'started_at': utc(), 'mode': options.mode, 'directory': str(self.directory),
                       'base_commit': git('rev-parse', 'HEAD').stdout.decode().strip(),
                       'platform': platform.platform(), 'python': sys.version, 'tools': {}, 'checks': [],
                       'cleanup': {'status': 'pending', 'scope': 'only sessions created by this verification run'},
                       'browser': {'status': 'not_run', 'reason': 'browser QA is separate; runner does not claim visual verification'}}
        self.source_before = source_inventory()
        self.report['source'] = self.source_before
        self.save()

    def save(self):
        atomic_json(self.report_path, self.report)

    def skip(self, name, reason):
        self.report['checks'].append({'name': name, 'status': 'skipped', 'reason': reason})
        self.save()

    def command(self, name, command, *, timeout=None, runtime=None):
        timeout = self.options.timeout if timeout is None else timeout
        log = self.logs / (name + '.log')
        check = {'name': name, 'command': list(map(str, command)), 'started_at': utc(), 'status': 'running', 'log': str(log)}
        self.report['checks'].append(check); self.save()
        print(name + ' ...', flush=True)
        owned = OwnedProcess(command, log, env=self.env)
        owned.runtime = runtime
        self.processes.append(owned)
        start = time.monotonic()
        try:
            try:
                code = owned.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                check.update(status='failed', exit_code=None, error='command deadline exceeded')
                raise VerificationFailure(name + ' timed out; inspect ' + str(log), 124) from error
            check.update(status='passed' if code == 0 else 'failed', exit_code=code)
            if code:
                raise VerificationFailure(name + ' failed with exit code ' + str(code) + '; inspect ' + str(log), code if 0 < code < 256 else 1)
        finally:
            owned.stop()
            check.update(finished_at=utc(), elapsed_seconds=round(time.monotonic() - start, 3))
            self.save()
        return log

    def preflight(self):
        if os.name != 'posix' or not hasattr(os, 'killpg'):
            raise VerificationFailure('the process-isolated institutional fixture currently requires POSIX')
        if self.options.mode == 'full' and not Path('/proc/self/stat').is_file():
            raise VerificationFailure('full lifecycle verification currently requires Linux procfs for orphan-safe cleanup')
        for tool in ('git', 'cmake', 'openssl'):
            executable = shutil.which(tool)
            if executable is None:
                raise VerificationFailure('missing prerequisite: ' + tool)
            result = subprocess.run([executable, 'version' if tool == 'openssl' else '--version'], stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, timeout=15)
            if result.returncode:
                raise VerificationFailure('unable to read prerequisite version: ' + tool)
            self.report['tools'][tool] = {'path': executable, 'version': result.stdout.splitlines()[0]}
        if self.options.build and shutil.which('c++') is None:
            raise VerificationFailure('building requires a C++ compiler and the documented Elements development dependencies')
        self.save()

    def build(self):
        if not self.options.build:
            self.skip('configure-build', 'explicit --no-build; existing artifacts will be validated')
            return
        self.command('configure-secp256k1', ['cmake', '-S', ROOT / 'src' / 'secp256k1', '-B', self.secp,
                     '-DBUILD_SHARED_LIBS=ON', '-DCMAKE_BUILD_TYPE=Release', '-DSECP256K1_BUILD_TESTS=OFF',
                     '-DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF', '-DSECP256K1_BUILD_CTIME_TESTS=OFF',
                     '-DSECP256K1_BUILD_BENCHMARK=OFF', '-DSECP256K1_ENABLE_MODULE_BPPP=OFF'])
        self.command('build-secp256k1', ['cmake', '--build', self.secp, '-j', self.options.jobs])
        self.command('configure-elements', ['cmake', '-S', ROOT, '-B', self.native,
                     '-DCMAKE_BUILD_TYPE=Release', '-DBUILD_GUI=OFF', '-DBUILD_TESTS=ON', '-DBUILD_FUZZ_BINARY=ON',
                     '-DWITH_BDB=ON', '-DWARN_INCOMPATIBLE_BDB=OFF', '-DWITH_ZMQ=OFF', '-DWITH_MULTIPROCESS=OFF'])
        self.command('build-elements', ['cmake', '--build', self.native, '--target', 'elementsd', 'elements-cli',
                     'test_elements', 'threshold_audit_replay', 'threshold_audit_vectors', '-j', self.options.jobs])

    def artifacts(self):
        if self.library is None:
            candidates = [self.secp / 'lib' / 'libsecp256k1.so', self.secp / 'lib' / 'libsecp256k1.dylib',
                          self.secp / 'libsecp256k1.so', self.secp / 'libsecp256k1.dylib']
            self.library = next((path for path in candidates if path.is_file()), None)
        if self.library is None or not self.library.is_file():
            raise VerificationFailure('shared secp256k1 library not found; build it or specify --library')
        required = ('elementsd', 'elements-cli', 'test_elements', 'threshold_audit_vectors')
        for name in required:
            file = self.native / 'bin' / name
            if not file.is_file() or not os.access(file, os.X_OK):
                raise VerificationFailure('missing native target ' + name + '; configure/build it or choose --build')
        config = self.native / 'test' / 'config.ini'
        parsed = configparser.ConfigParser(); parsed.read(config)
        if not parsed.has_section('components') or not parsed.getboolean('components', 'USE_BDB', fallback=False):
            raise VerificationFailure('the institutional sandbox and legacy DynaFed baseline require WITH_BDB=ON')
        if Path(parsed.get('environment', 'SRCDIR')).resolve() != ROOT:
            raise VerificationFailure('native test configuration belongs to another source checkout')
        self.env['THRESHOLD_AUDIT_SECP256K1'] = str(self.library)
        self.env['SECP256K1_ZKP_LIBRARY'] = str(self.library)
        self.report['artifacts'] = {'native_build': str(self.native), 'secp_build': str(self.secp),
                                    'library': str(self.library), 'library_sha256': hashlib.sha256(self.library.read_bytes()).hexdigest(),
                                    'built_by_this_run': self.options.build,
                                    'source_binary_binding': 'CMake configure/build executed by this run' if self.options.build else 'existing artifacts supplied by operator; source correspondence is not attested',
                                    'binaries': {name: hashlib.sha256((self.native / 'bin' / name).read_bytes()).hexdigest() for name in required}}
        self.save()

    def quick(self):
        review = ROOT / 'contrib' / 'threshold-audit' / 'review'
        self.command('public-python-vectors', [sys.executable, review / 'vectors.py', '--library', self.library, '--check'])
        self.command('public-native-vectors', [self.native / 'bin' / 'threshold_audit_vectors', review / 'vectors' / 'public-v1.json'])
        self.command('python-tests', [sys.executable, '-m', 'unittest', 'discover', '-s', ROOT / 'contrib' / 'threshold-audit', '-p', 'test_*.py', '-v'], runtime=self.runtimes)
        self.command('review-python-tests', [sys.executable, '-m', 'unittest', 'discover', '-s', review, '-p', 'test_*.py', '-v'])
        self.command('native-tests', [self.native / 'bin' / 'test_elements',
                     '--run_test=blind_tests,psbt_wallet_tests,spend_tests,dynafed_tests,headers_sync_chainwork_tests', '--report_level=detailed'])
        self.command('review-inventory', [sys.executable, review / 'inventory.py', '--output', self.directory / 'review-inventory.json'])
        if self.options.skip_patch_export:
            self.skip('review-patch-export', 'explicit --skip-patch-export')
        else:
            self.command('review-patch-export', [sys.executable, ROOT / 'contrib' / 'threshold-audit' / 'export_review.py',
                         '--output', self.directory / 'review-patches'])

    def functional(self):
        tests = [('native-audit', 'feature_threshold_audit.py', '--descriptors'),
                 ('native-assets', 'feature_threshold_audit_assets.py', '--descriptors'),
                 ('native-guardians', 'feature_threshold_audit_guardians.py', '--descriptors'),
                 ('baseline-dynafed', 'feature_dynafed.py', '--legacy-wallet'),
                 ('baseline-psbt', 'rpc_psbt.py', '--descriptors')]
        for offset, (name, filename, wallet) in enumerate(tests):
            self.command(name, [sys.executable, ROOT / 'test' / 'functional' / filename,
                         '--configfile=' + str(self.native / 'test' / 'config.ini'),
                         '--tmpdir=' + str(self.runtimes / name), '--portseed=' + str(self.options.port_seed + offset), wallet], runtime=self.runtimes)
        replay = self.native / 'bin' / 'threshold_audit_replay'
        if not replay.is_file():
            raise VerificationFailure('full mode requires threshold_audit_replay native target')
        corpus = self.directory / 'public-fuzz-corpus'
        self.command('public-fuzz-seeds', [sys.executable, ROOT / 'contrib' / 'threshold-audit' / 'make_fuzz_corpus.py', '--output', corpus])
        self.command('native-public-fuzz-replay', [replay, corpus])

    def start_sandbox(self, runtime, *, resume=False):
        index = sum(check['name'].startswith('sandbox-start-') for check in self.report['checks']) + 1
        name = 'sandbox-start-' + str(index)
        command = [sys.executable, '-u', '-m', 'settlement.sandbox', '--resume' if resume else '--directory', runtime,
                   '--daemon', self.native / 'bin' / 'elementsd', '--library', self.library]
        log = self.logs / (name + '.log')
        owned = OwnedProcess(command, log, env=self.env); self.processes.append(owned); self.sandbox = owned
        owned.runtime = runtime
        check = {'name': name, 'command': list(map(str, command)), 'started_at': utc(), 'status': 'running', 'log': str(log)}
        self.report['checks'].append(check); self.save()
        deadline = time.monotonic() + min(self.options.timeout, 300)
        ready_path = runtime / 'ready.json'
        while time.monotonic() < deadline:
            if owned.process.poll() is not None:
                check.update(status='failed', exit_code=owned.process.returncode, finished_at=utc()); self.save()
                raise VerificationFailure(name + ' exited before readiness; inspect ' + str(log))
            if ready_path.exists():
                try:
                    ready = json.loads(ready_path.read_text())
                    # Ignore readiness left by the previous owned process.
                    if ready.get('pid') == owned.process.pid:
                        import urllib.request
                        with urllib.request.urlopen(ready['url'] + 'api/session', timeout=5) as response:
                            if response.status == 200:
                                check.update(status='passed', exit_code=0, finished_at=utc(), url=ready['url'])
                                self.save(); return
                except (OSError, ValueError):
                    pass
            time.sleep(.2)
        check.update(status='failed', exit_code=None, finished_at=utc(), error='readiness deadline exceeded'); self.save()
        raise VerificationFailure(name + ' readiness timed out; inspect ' + str(log), 124)

    def repeated_rotation(self):
        runtime = self.runtimes / 'institutional-abc'
        self.start_sandbox(runtime)
        phases = ('seed', 'stage-b', 'stage-c', 'finish')
        for phase in phases:
            self.command('abc-' + phase, [sys.executable, '-u', '-m', 'settlement.repeated_rotation_smoke', runtime, '--phase', phase])
            if phase in {'stage-b', 'stage-c'}:
                self.sandbox.stop(); self.sandbox = None
                self.start_sandbox(runtime, resume=True)
        # Completed-state restart must preserve C-only membership and outcomes.
        self.sandbox.stop(); self.sandbox = None
        self.start_sandbox(runtime, resume=True)
        self.command('abc-completed-restart', [sys.executable, '-u', '-m', 'settlement.repeated_rotation_smoke', runtime, '--phase', 'finish'])
        self.sandbox.stop(); self.sandbox = None

    def runtime_faults(self):
        directory = self.runtimes / 'runtime-faults'
        self.command('runtime-faults', [sys.executable, '-u', '-m', 'settlement.runtime_faults',
                     '--work-dir', directory, '--daemon', self.native / 'bin' / 'elementsd', '--library', self.library], runtime=directory)

    def cleanup(self):
        self.cleaning = True
        errors = []
        for process in reversed(self.processes):
            try:
                process.stop()
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                errors.append(type(error).__name__ + ': ' + str(error))
        self.report['cleanup'] = {'status': 'passed' if not errors else 'failed',
                                  'scope': 'only sessions created by this verification run', 'errors': errors}
        self.save()
        self.cleaning = False
        return errors

    def run(self):
        code = 1
        try:
            self.preflight(); self.build(); self.artifacts(); self.quick()
            if self.options.mode == 'full':
                self.functional(); self.repeated_rotation(); self.runtime_faults()
            else:
                self.skip('native-functional-and-abc', 'quick mode; use --mode full for native regressions and repeated rotation')
            after = source_inventory()
            self.report['source_unchanged'] = after == self.source_before
            if not self.report['source_unchanged']:
                raise VerificationFailure('source changed during verification; results do not cover one stable source snapshot')
            self.report['status'], code = 'passed', 0
        except VerificationFailure as error:
            self.report.update(status='interrupted' if isinstance(error, Interrupted) else 'failed', error=str(error), exit_code=error.exit_code)
            code = error.exit_code
        except Exception as error:
            self.report.update(status='failed', error=type(error).__name__ + ': ' + str(error), exit_code=1)
        finally:
            cleanup_errors = self.cleanup()
            if cleanup_errors:
                self.report['status'], code = 'failed', 1
            self.report.update(finished_at=utc(), exit_code=code)
            self.save()
        print(json.dumps({'status': self.report['status'], 'report': str(self.report_path), 'exit_code': code}), flush=True)
        return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('quick', 'full'), default='quick')
    parser.add_argument('--work-dir', type=Path, help='new/empty private output directory; default is an OS temporary directory')
    build = parser.add_mutually_exclusive_group()
    build.add_argument('--build', dest='build', action='store_true', help='configure/build bundled library and native targets (default)')
    build.add_argument('--no-build', dest='build', action='store_false', help='use explicitly supplied existing artifacts')
    parser.set_defaults(build=True)
    parser.add_argument('--native-build', type=Path)
    parser.add_argument('--secp-build', type=Path)
    parser.add_argument('--library', type=Path)
    parser.add_argument('--jobs', type=int, default=min(4, os.cpu_count() or 1))
    parser.add_argument('--timeout', type=int, default=3600, help='per-command deadline in seconds')
    parser.add_argument('--port-seed', type=int, default=140, help='native functional-test port allocation seed')
    parser.add_argument('--skip-patch-export', action='store_true', help='explicitly omit patch export/apply verification')
    options = parser.parse_args()
    if options.jobs < 1 or options.timeout < 1 or not 0 <= options.port_seed <= 1000:
        parser.error('jobs/timeout must be positive and port-seed must be between 0 and 1000')
    try:
        verifier = Verifier(options)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, 'verification setup failed: ' + str(error) + '\n')
    def interrupted(number, _frame):
        if verifier.cleaning or getattr(verifier, 'interrupted', False):
            return
        verifier.interrupted = True
        raise Interrupted('verification interrupted by signal ' + str(number), 128 + number)
    signal.signal(signal.SIGINT, interrupted); signal.signal(signal.SIGTERM, interrupted)
    print('Private verification directory: ' + str(verifier.directory), flush=True)
    raise SystemExit(verifier.run())


if __name__ == '__main__':
    main()
