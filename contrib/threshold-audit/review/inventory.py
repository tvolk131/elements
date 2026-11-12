#!/usr/bin/env python3
"""Fingerprint the public review source snapshot, never a sandbox runtime.

The base commit plus source_tree_digest identifies the reviewed working tree.
Generated reports belong outside the repository. Runtime JSON, credentials,
private guardian state, build output and Python caches are excluded by design.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[2]
PROTOTYPE = HERE.parent
SOURCE_SUFFIXES = {'.py', '.cpp', '.h', '.md', '.html', '.css', '.js', '.sh', '.txt'}
PUBLIC_JSON = {PROTOTYPE / 'measurements.example.json', HERE / 'vectors' / 'public-v1.json'}


def git(*arguments, repository=REPOSITORY):
    return subprocess.check_output(['git', '-C', str(repository), *arguments], stderr=subprocess.DEVNULL)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def source_files(repository=REPOSITORY):
    repository = Path(repository).resolve()
    prototype = repository / 'contrib' / 'threshold-audit'
    paths = set()
    # All experiment source is included, even before its first commit. The
    # remaining base tree is identified by base_commit, so retain every native
    # tracked overlay as well as the added functional/consensus files.
    for path in prototype.rglob('*'):
        if ('__pycache__' not in path.parts and path.is_file() and not path.is_symlink()
                and (path.suffix in SOURCE_SUFFIXES or path in {
                    prototype / 'measurements.example.json', prototype / 'review' / 'vectors' / 'public-v1.json'})):
            paths.add(path)
    changed = git('diff', '--name-only', '-z', 'HEAD', repository=repository).split(b'\x00')
    added = git('ls-files', '--others', '--exclude-standard', '-z', repository=repository).split(b'\x00')
    for item in (*changed, *added):
        if not item:
            continue
        relative = Path(item.decode('utf-8'))
        path = repository / relative
        if (relative.parts[0] in {'src', 'test', 'contrib', 'cmake'} or relative.name == 'CMakeLists.txt'):
            if path.is_file() and not path.is_symlink() and path.suffix in SOURCE_SUFFIXES:
                paths.add(path)
    result = []
    for path in sorted(paths):
        if not path.resolve().is_relative_to(repository) or '__pycache__' in path.parts:
            continue
        data = path.read_bytes()
        result.append({'path': path.relative_to(repository).as_posix(), 'size': len(data),
                       'sha256': hashlib.sha256(data).hexdigest()})
    return result


def inventory(repository=REPOSITORY):
    repository = Path(repository).resolve()
    files = source_files(repository)
    base = git('rev-parse', 'HEAD', repository=repository).decode().strip()
    status = git('status', '--porcelain', '--untracked-files=normal', repository=repository).decode()
    submodules = git('submodule', 'status', '--recursive', repository=repository).decode().splitlines()
    return {'format': 'elements-threshold-audit-review-inventory-v1',
            'generated_at_utc': datetime.now(timezone.utc).isoformat(), 'base_commit': base,
            'working_tree_dirty': bool(status), 'submodules': submodules,
            'source_tree_digest': hashlib.sha256(canonical(files)).hexdigest(), 'files': files,
            'scope': 'All allowlisted experimental source/public fixtures plus modified/added native and test overlay; unchanged dependencies are pinned by base_commit and submodules.',
            'exclusions': ['sandbox runtime directories', 'credential/private-state JSON', '__pycache__', 'build output', 'generated verification reports'],
            'review_status': 'Engineering review package only; not an independent cryptographic audit or certification.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='write public source inventory JSON outside source tree')
    options = parser.parse_args()
    result = inventory()
    encoded = json.dumps(result, sort_keys=True, indent=2) + '\n'
    if options.output:
        options.output.parent.mkdir(parents=True, exist_ok=True)
        options.output.write_text(encoded)
        print(json.dumps({'output': str(options.output), 'source_tree_digest': result['source_tree_digest'],
                          'file_count': len(result['files']), 'base_commit': result['base_commit']}))
    else:
        print(encoded, end='')


if __name__ == '__main__':
    main()
