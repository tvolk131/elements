#!/usr/bin/env python3
"""Export the experimental fork as ordered, verified review patches.

Reads Git and the working tree only. It does not stage, commit, reset or create a
worktree. Groups are review categories; intermediate patches are not promised to
build independently. The complete series is checked against an archived base.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[2]
NATIVE_TRACKED = {
    'src/CMakeLists.txt', 'src/blind.cpp', 'src/blind.h', 'src/blindpsbt.cpp', 'src/blindpsbt.h',
    'src/chainparams.cpp', 'src/chainparamsbase.cpp', 'src/common/messages.cpp', 'src/common/types.h',
    'src/consensus/params.h', 'src/dynafed.cpp', 'src/headerssync.cpp', 'src/headerssync.h',
    'src/interfaces/chain.h', 'src/kernel/chainparams.cpp', 'src/node/interfaces.cpp',
    'src/node/miner.cpp', 'src/node/miner.h', 'src/policy/policy.cpp', 'src/primitives/block.cpp',
    'src/primitives/block.h',
    'src/primitives/transaction.cpp',
    'src/primitives/txwitness.cpp', 'src/primitives/txwitness.h', 'src/psbt.cpp', 'src/psbt.h',
    'src/rpc/blockchain.cpp', 'src/rpc/mining.cpp', 'src/rpc/rawtransaction.cpp',
    'src/validation.cpp', 'src/wallet/rpc/elements.cpp', 'src/wallet/spend.cpp', 'src/wallet/wallet.cpp',
}
TEST_TRACKED = {'src/test/fuzz/CMakeLists.txt', 'src/test/headers_sync_chainwork_tests.cpp',
                'test/functional/test_framework/messages.py', 'test/functional/test_runner.py'}
EXTRA_NATIVE = {'src/threshold_audit.cpp', 'src/threshold_audit.h',
                'src/threshold_audit_governance.cpp', 'src/threshold_audit_governance.h',
                'src/threshold_audit_validation.cpp', 'src/threshold_audit_validation.h'}
EXTRA_TEST = {'src/test/fuzz/threshold_audit.cpp', 'test/functional/feature_threshold_audit.py',
              'test/functional/feature_threshold_audit_assets.py',
              'test/functional/feature_threshold_audit_authorization.py',
              'test/functional/feature_threshold_audit_recovery.py',
              'test/functional/feature_threshold_audit_guardians.py'}
SOURCE_SUFFIXES = {'.py', '.cpp', '.h', '.md', '.html', '.css', '.js', '.ts', '.tsx', '.sh', '.txt'}
# Exact project files that the general rules below would refuse: ignore files and
# the wallet UI's package and compiler settings plus its committed test fixture.
PUBLIC_EXTRA = {'.gitignore', 'settlement/ui/.gitignore', 'settlement/ui/.prettierignore',
                'settlement/ui/package.json', 'settlement/ui/package-lock.json',
                'settlement/ui/tsconfig.json', 'settlement/ui/src/fixtures/sealed-disclosure.json'}
GROUPS = ('01-native-consensus-wallet', '02-native-tests', '03-crypto-guardian-models',
          '04-institutional-settlement', '05-review-verification-docs')


def git(*arguments, root=ROOT, check=True):
    result = subprocess.run(['git', *arguments], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace').strip())
    return result


def category(path):
    if path in NATIVE_TRACKED or path in EXTRA_NATIVE:
        return GROUPS[0]
    if path in TEST_TRACKED or path in EXTRA_TEST:
        return GROUPS[1]
    if path == 'contrib/README.md':
        return GROUPS[4]
    prefix = 'contrib/threshold-audit/'
    if not path.startswith(prefix):
        return None
    relative = PurePosixPath(path[len(prefix):])
    if str(relative) in PUBLIC_EXTRA:
        return GROUPS[3] if relative.parts[0] == 'settlement' else GROUPS[4]
    if any(part.startswith('.') or part in {'__pycache__', 'runtime', 'runtimes', 'node_modules', 'build'} for part in relative.parts):
        return None
    if relative.suffix == '.json':
        # Deliberately narrow public fixture namespace. Never export arbitrary
        # JSON under a demo runtime, even when it happens to live in the repo.
        if str(relative) not in {'measurements.example.json', 'review/vectors/public-v1.json'}:
            return None
        if any(word in relative.name.lower() for word in ('credential', 'password', 'private', 'service', 'endpoint', 'token')):
            return None
    elif relative.suffix not in SOURCE_SUFFIXES:
        return None
    if relative.parts[0] == 'settlement':
        return GROUPS[3]
    if relative.suffix == '.md' or relative.parts[0] == 'review' or relative.name in {'verify.py', 'export_review.py', 'test_verification_tools.py', 'manage.py', 'test_manage.py'}:
        return GROUPS[4]
    return GROUPS[2]


def changed_files(base, root=ROOT):
    tracked = {item.decode() for item in git('diff', '--name-only', '-z', base, '--', root=root).stdout.split(b'\0') if item}
    untracked = {item.decode() for item in git('ls-files', '--others', '--exclude-standard', '-z', root=root).stdout.split(b'\0') if item}
    unknown = sorted(path for path in tracked if category(path) is None)
    if unknown:
        raise ValueError('unclassified tracked changes require review before export: ' + ', '.join(unknown))
    selected = sorted(path for path in tracked | untracked if category(path) is not None)
    return selected, tracked, sorted(untracked - set(selected))


def snapshot(path, root=ROOT):
    file = root / path
    if file.is_symlink():
        raise ValueError('review source must be a regular file: ' + path)
    if not file.exists():
        return {'path': path, 'sha256': None, 'size': 0, 'mode': None}
    if not file.is_file():
        raise ValueError('review source must be a regular file: ' + path)
    data = file.read_bytes()
    return {'path': path, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data),
            'mode': '100755' if file.stat().st_mode & stat.S_IXUSR else '100644'}


def verify_archive(root, base, patches, expected):
    with tempfile.TemporaryDirectory(prefix='elements-review-apply-') as directory:
        directory = Path(directory)
        archive = directory / 'base.tar'
        with archive.open('wb') as stream:
            subprocess.run(['git', 'archive', '--format=tar', base], cwd=root, stdout=stream, check=True)
        tree = directory / 'tree'
        tree.mkdir()
        with tarfile.open(archive) as source:
            members = source.getmembers()
            for member in members:
                path = PurePosixPath(member.name)
                if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                    raise ValueError('base archive contains unsupported file type or path: ' + member.name)
            # Archive comes from the selected local Git base; paths and types
            # were checked above. Never follow a symlink out of the empty tree.
            if hasattr(tarfile, 'data_filter'):
                source.extractall(tree, members=members, filter='data')
            else:
                source.extractall(tree, members=members)
        for patch in patches:
            git('apply', '--check', str(patch), root=tree)
            git('apply', str(patch), root=tree)
        for wanted in expected:
            actual = snapshot(wanted['path'], tree)
            if actual != wanted:
                raise ValueError('complete patch series does not reconstruct source: ' + wanted['path'])
    return {'status': 'passed', 'method': 'sequential git apply against git archive of base; final file digests and modes match',
            'intermediate_builds_checked': False}


def export(output, base='HEAD', *, root=ROOT, check_apply=True):
    root = Path(root).resolve()
    output = Path(output).resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError('review output must be a new or empty directory')
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(output, 0o700)
    base_sha = git('rev-parse', '--verify', base + '^{commit}', root=root).stdout.decode().strip()
    paths, tracked, excluded = changed_files(base_sha, root)
    if not paths:
        raise ValueError('no authorized experimental changes to export')
    expected = [snapshot(path, root) for path in paths]
    patches, groups = [], []
    for group in GROUPS:
        selected = [path for path in paths if category(path) == group]
        if not selected:
            continue
        chunks = []
        existing = [path for path in selected if path in tracked]
        if existing:
            chunks.append(git('diff', '--binary', '--full-index', '--no-ext-diff', base_sha, '--', *existing, root=root).stdout)
        for path in selected:
            if path in tracked:
                continue
            result = git('diff', '--no-index', '--binary', '--full-index', '--no-ext-diff', '--', '/dev/null', path, root=root, check=False)
            if result.returncode not in {0, 1}:
                raise RuntimeError(result.stderr.decode(errors='replace'))
            chunks.append(result.stdout)
        data = b''.join(chunks)
        patch = output / (group + '.patch')
        patch.write_bytes(data)
        os.chmod(patch, 0o600)
        patches.append(patch)
        groups.append({'patch': patch.name, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'files': selected})
    if changed_files(base_sha, root)[0] != paths or [snapshot(path, root) for path in paths] != expected:
        raise RuntimeError('source changed during export; retry when editing has settled')
    (output / 'series').write_text(''.join(patch.name + '\n' for patch in patches))
    verification = verify_archive(root, base_sha, patches, expected) if check_apply else {'status': 'not_run', 'intermediate_builds_checked': False}
    manifest = {'format': 'elements-threshold-audit-review-v1', 'base_commit': base_sha,
                'scope': 'authorized experimental fork changes; no index or worktree mutation',
                'ordering': 'review categories, not an assertion that intermediate patches compile',
                'patches': groups, 'files': expected,
                'excluded_untracked': {'count': len(excluded), 'policy': 'unclassified files, caches and runtime data are excluded; private names are not exported'},
                'verification': verification}
    (output / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    (output / 'README.md').write_text('# Experimental fork review series\n\n'
        'Apply patches in `series` order to the exact `base_commit` in `manifest.json`. '
        'The exporter verified clean sequential application and final file hashes. '
        'Categories are review boundaries; intermediate patch buildability is not claimed. '
        'Build/test results belong to the separate verification report. '
        'Runtime credentials, node data, private shares and Python caches are excluded.\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--base', default='HEAD', help='Git commit the patches apply to; verify.py passes the branch point from master')
    parser.add_argument('--skip-apply-check', action='store_true', help='export only; report explicitly records verification not run')
    options = parser.parse_args()
    try:
        manifest = export(options.output, options.base, check_apply=not options.skip_apply_check)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, 'review export failed: ' + str(error) + '\n')
    print(json.dumps({'output': str(options.output.resolve()), 'base_commit': manifest['base_commit'],
                      'patches': len(manifest['patches']), 'files': len(manifest['files']),
                      'verification': manifest['verification']['status']}))


if __name__ == '__main__':
    main()
