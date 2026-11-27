"""Publish two validated regular files and reconcile interrupted creates."""

import base64
import difflib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlencode

from handoff import output
from target import REPO, TARGETS, paths_for


class EvidenceWithdrawn(Exception):
    """There is no eligible input or existing PR to report."""


def api(token, path, data=None):
    env = os.environ.copy()
    if token:
        env['GH_TOKEN'] = token
    command = ['gh', 'api', '--hostname', 'github.com', path]
    if data is not None:
        command += ['--method', 'POST', '--input', '-']
    result = subprocess.run(command, input=json.dumps(data) if data is not None else None,
                            text=True, capture_output=True, env=env, timeout=30)
    if result.returncode:
        if '(HTTP 404)' in result.stderr:
            raise HTTPError(path, 404, 'Not found', None, None)
        raise OSError('GitHub request failed')
    return json.loads(result.stdout)


def validate(original, source, test, examples):
    lines = difflib.SequenceMatcher(None, original.splitlines(), source.splitlines(), autojunk=False)
    count = sum(max(b - a, d - c) for op, a, b, c, d in lines.get_opcodes() if op != 'equal')
    if not 0 < count <= 80 or not 0 < len(test.encode()) <= 16000 or len(source.encode()) > len(original.encode()) + 16000:
        raise ValueError('Invalid change size')
    if (examples and not any(e in test for e in examples)) or '\x00' in source + test:
        raise ValueError('Missing synthetic regression')


def candidate(case, original, path):
    if path.stat().st_size > 64000:
        raise ValueError
    result = json.loads(path.read_text())
    if result == {'status': 'unchanged', 'edits': [], 'test': ''}:
        return None
    if set(result) != {'status', 'edits', 'test'} or result['status'] != 'changed' or not 1 <= len(result['edits']) <= 12:
        raise ValueError
    source = original
    for edit in result['edits']:
        before, after = edit['before'], edit['after']
        if set(edit) != {'before', 'after'} or not before or source.count(before) != 1:
            raise ValueError
        source = source.replace(before, after, 1)
    validate(original, source, result['test'], case['examples'])
    return source, result['test']


class Publisher:
    def __init__(self, case):
        self.case = case
        self.base = 'websentry-ai/' + REPO
        self.branch = 'codex/dlp-enhancer-' + case['id']
        self.sha = case['base_sha']
        self.source, self.test = paths_for(case)
        self.token = os.environ.get('PR_TOKEN')
        # User tokens create pull_request events; the built-in workflow token suppresses downstream runs.
        if os.getenv('GITHUB_ACTIONS') == 'true' and not (self.token or '').startswith(('ghp_', 'github_pat_')):
            raise ValueError('Expected a repository-scoped PAT')

    def remote(self, path, data=None):
        return api(self.token, 'repos/' + self.base + path, data)

    def existing_pr(self):
        query = urlencode({'state': 'all', 'base': 'staging', 'head': 'websentry-ai:' + self.branch})
        for pr in self.remote('/pulls?' + query):
            head = pr['head']
            if (head['ref'] == self.branch and (head.get('repo') or {}).get('full_name', '').lower() == self.base.lower()
                    and pr['base']['ref'] == 'staging' and pr['base']['repo']['full_name'] == self.base):
                return pr
        return None

    def ref(self):
        try:
            return self.remote('/git/ref/heads/' + self.branch)['object']['sha']
        except HTTPError as error:
            if error.code != 404:
                raise
            return None

    def verified_branch(self, commit, original):
        change = self.remote('/commits/' + commit)
        if [p['sha'] for p in change['parents']] != [self.sha]:
            raise ValueError
        changed = {f['filename']: f['status'] for f in change['files']}
        legacy_test = TARGETS[self.case['detector'], self.case['pattern']][1]
        # Interrupted runs from the first workflow version used a fixed regression filename.
        test = legacy_test if legacy_test in changed else self.test
        if changed != {self.source: 'modified', test: 'added'}:
            raise ValueError('Unexpected detector or test path')
        tree = self.remote('/git/trees/' + change['commit']['tree']['sha'] + '?recursive=1')
        selected = {e['path']: e for e in tree['tree'] if e['path'] in (self.source, test)}
        contents = []
        for path in (self.source, test):
            entry = selected[path]
            max_size = 16000 if path == test else len(original.encode()) + 16000
            if entry['type'] != 'blob' or entry['mode'] != '100644' or entry['size'] > max_size:
                raise ValueError
            blob = self.remote('/git/blobs/' + entry['sha'])
            contents.append(base64.b64decode(blob['content']).decode())
        validate(original, *contents, self.case['examples'])

    def open(self, artifact):
        pr = self.existing_pr()
        if not pr and not self.case['examples']:
            raise EvidenceWithdrawn
        baseline = subprocess.check_output(['git', '-C', 'detector', 'ls-tree', self.sha, '--', self.source, self.test], text=True)
        if len(baseline.splitlines()) != 1 or not baseline.startswith('100644 blob ') or not baseline.rstrip().endswith('\t' + self.source):
            raise ValueError('Expected an existing detector and new test')
        original = subprocess.check_output(['git', '-C', 'detector', 'show', self.sha + ':' + self.source], text=True)
        if pr:
            self.verified_branch(pr['head']['sha'], original)
            return pr
        commit = self.ref()
        if not commit:
            files = candidate(self.case, original, artifact)
            if files is None:
                return None
            base_tree = self.remote('/git/commits/' + self.sha)['tree']['sha']
            tree = self.remote('/git/trees', {'base_tree': base_tree, 'tree': [
                {'path': p, 'mode': '100644', 'type': 'blob', 'content': content}
                for p, content in zip((self.source, self.test), files)]})
            result = self.remote('/git/commits', {'message': 'Cover a synthetic detector regression', 'tree': tree['sha'], 'parents': [self.sha]})
            try:
                self.remote('/git/refs', {'ref': 'refs/heads/' + self.branch, 'sha': result['sha']})
            except (OSError, subprocess.TimeoutExpired):
                if not self.ref():
                    raise
            commit = self.ref()
        self.verified_branch(commit, original)
        try:
            return self.remote('/pulls', {'head': self.branch, 'base': 'staging',
                                            'draft': True, 'title': 'DLP Enhancer: ' + self.case['pattern'],
                                            'body': 'Synthetic regression for case ' + self.case['id'] + '. Review detector behavior and CI.'})
        except (OSError, subprocess.TimeoutExpired):
            pr = self.existing_pr()
            if not pr or pr['head']['sha'] != commit:
                raise
            return pr


def confirm_ci():
    workflow = 'detector_tests.yml' if REPO == 'dlp-detector' else 'test.yml'
    path = f'repos/websentry-ai/{REPO}/actions/workflows/{workflow}/runs?' + urlencode({
        'event': 'pull_request', 'head_sha': os.environ['PR_SHA']})
    for _ in range(12):
        runs = api(os.environ.get('GH_TOKEN'), path)['workflow_runs']
        if any(run['head_branch'] == os.environ['PR_BRANCH'] and run['head_repository']['full_name'] == 'websentry-ai/' + REPO
               for run in runs):
            return
        time.sleep(5)
    raise ValueError


if __name__ == '__main__':
    try:
        if sys.argv[1] == 'confirm-ci':
            confirm_ci()
        else:
            pr = Publisher(json.loads(os.environ['CASE'])).open(Path(sys.argv[1]))
            if pr:
                output('pr', pr['number'])
                output('sha', pr['head']['sha'])
            else:
                output('unchanged', True)
    except EvidenceWithdrawn:
        # No PR or unchanged output makes the reporting job release the case for retry.
        pass
    except Exception:
        sys.exit('Detector CI run unconfirmed.' if sys.argv[1] == 'confirm-ci' else 'Draft publication failed.')
