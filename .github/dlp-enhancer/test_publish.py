"""Exercise the publishing entry point with the GitHub transport replaced at its IO boundary."""

import base64
from contextlib import ExitStack
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from publish import Publisher
from target import TARGETS


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.dict(os.environ, {'PR_TOKEN': 'github_pat_test_fixture'}))
        self.temp = stack.enter_context(tempfile.TemporaryDirectory())
        detector, pattern = next(iter(TARGETS))
        self.pub = Publisher({'detector': detector, 'pattern': pattern, 'id': 'fixture', 'base_sha': 'a' * 40,
                              'examples': ['synthetic example']})
        self.files = {self.pub.source: 'before\n'.encode(), self.pub.test: b'synthetic example\n'}
        self.status = {self.pub.source: 'modified', self.pub.test: 'added'}
        self.ref = self.pr = None
        self.mode = '100644'
        self.creates = 0
        stack.enter_context(patch.object(self.pub, 'remote', side_effect=self.github))
        stack.enter_context(patch.object(subprocess, 'check_output', side_effect=self.git))
        self.artifact = Path(self.temp, 'proposal.json')
        self.artifact.write_text('{"status":"changed","edits":[{"before":"before","after":"after"}],"test":"synthetic example"}')

    def git(self, args, **kwargs):
        if 'ls-tree' in args:
            return '100644 blob abc\t' + self.pub.source + '\n'
        return 'before\n'

    def github(self, path, data=None):
        if path.startswith('/pulls?'):
            return [self.pr] if self.pr else []
        if path.startswith('/git/ref/heads/'):
            if self.ref:
                return {'object': {'sha': self.ref}}
            raise HTTPError(path, 404, 'missing', None, None)
        if path == '/git/commits/' + self.pub.sha:
            return {'tree': {'sha': 'base'}}
        if path == '/git/trees':
            self.assertEqual(data['base_tree'], 'base')
            self.files = {e['path']: e['content'].encode() for e in data['tree']}
            return {'sha': 'tree'}
        if path == '/git/commits':
            self.assertEqual(data['parents'], [self.pub.sha])
            return {'sha': 'commit'}
        if path == '/git/refs':
            self.ref = data['sha']
            raise TimeoutError('response lost after ref creation')
        if path == '/commits/commit':
            return {'parents': [{'sha': self.pub.sha}], 'commit': {'tree': {'sha': 'tree'}},
                    'files': [{'filename': p, 'status': s} for p, s in self.status.items()]}
        if path.startswith('/git/trees/tree?'):
            return {'tree': [{'path': p, 'mode': self.mode, 'type': 'blob', 'size': len(v), 'sha': str(i)}
                             for i, (p, v) in enumerate(self.files.items())]}
        if path.startswith('/git/blobs/'):
            return {'content': base64.b64encode(list(self.files.values())[int(path.rsplit('/', 1)[1])]).decode()}
        if path == '/pulls':
            self.assertTrue(data['draft'])
            self.assertEqual(data['base'], 'staging')
            self.creates += 1
            repo = {'full_name': self.pub.base}
            self.pr = {'number': 7, 'head': {'sha': self.ref, 'ref': self.pub.branch, 'repo': repo},
                       'base': {'ref': 'staging', 'repo': repo}}
            raise TimeoutError('response lost after PR creation')
        self.fail(path)

    def test_recovers_both_lost_responses_and_replays_without_the_artifact(self):
        self.assertEqual(self.pub.open(self.artifact)['number'], 7)
        self.artifact.unlink()
        self.assertEqual(self.pub.open(self.artifact)['number'], 7)
        self.assertEqual(self.creates, 1)

    def test_rejects_extra_path_and_symlink_on_recovered_branch(self):
        self.ref = 'commit'
        self.status['.github/workflows/unexpected.yml'] = 'added'
        with self.assertRaises(ValueError):
            self.pub.open(self.artifact)
        del self.status['.github/workflows/unexpected.yml']
        self.mode = '120000'
        with self.assertRaises(ValueError):
            self.pub.open(self.artifact)
        self.assertEqual(self.creates, 0)
