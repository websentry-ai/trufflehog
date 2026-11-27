"""Exercise the publishing entry point with the GitHub transport replaced at its IO boundary."""

import base64
import json
from contextlib import ExitStack
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import handoff
from publish import EvidenceWithdrawn, Publisher, report_publication
from target import TARGETS


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.dict(os.environ, {'PR_TOKEN': 'github_pat_test_fixture'}))
        self.temp = stack.enter_context(tempfile.TemporaryDirectory())
        detector, pattern = next(iter(TARGETS))
        self.pub = Publisher({'detector': detector, 'pattern': pattern, 'id': '12345678-1234-1234-1234-123456789abc', 'base_sha': 'a' * 40,
                              'examples': ['synthetic example']})
        self.files = {self.pub.source: b'after\n', self.pub.test: b'synthetic example\n'}
        self.status = {self.pub.source: 'modified', self.pub.test: 'added'}
        self.baseline_files = {self.pub.source}
        self.ref = self.pr = None
        self.mode = '100644'
        self.creates = 0
        stack.enter_context(patch.object(self.pub, 'remote', side_effect=self.github))
        stack.enter_context(patch.object(subprocess, 'check_output', side_effect=self.git))
        self.artifact = Path(self.temp, 'proposal.json')
        self.artifact.write_text('{"status":"changed","edits":[{"before":"before","after":"after"}],"test":"synthetic example"}')

    def git(self, args, **kwargs):
        if 'ls-tree' in args:
            paths = args[args.index('--') + 1:]
            return ''.join(f'100644 blob abc\t{path}\n' for path in paths if path in self.baseline_files)
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
            self.pr = {'number': 7, 'state': 'open', 'merged_at': None, 'head': {'sha': self.ref, 'ref': self.pub.branch, 'repo': repo},
                       'base': {'ref': 'staging', 'repo': repo}}
            raise TimeoutError('response lost after PR creation')
        self.fail(path)

    def test_recovers_both_lost_responses_and_replays_without_the_artifact(self):
        self.assertEqual(self.pub.open(self.artifact)['number'], 7)
        self.artifact.unlink()
        self.assertEqual(self.pub.open(self.artifact)['number'], 7)
        self.assertEqual(self.creates, 1)

    def test_unchanged_creates_nothing_but_an_absent_artifact_fails(self):
        self.artifact.write_text('{"status":"unchanged","edits":[],"test":""}')
        self.assertIsNone(self.pub.open(self.artifact))
        self.assertEqual(self.creates, 0)
        self.artifact.unlink()
        with self.assertRaises(FileNotFoundError):
            self.pub.open(self.artifact)

    def test_closed_draft_is_reported_as_closed_and_never_reopened(self):
        self.pub.open(self.artifact)
        self.pr['state'] = 'closed'
        with patch('publish.output') as output:
            report_publication(self.pub.open(self.artifact))
            output.assert_called_once_with('closed_pr', 7)
        self.assertEqual(self.creates, 1)
        env = {'CASE_ID': self.pub.case['id'], 'PUBLISH_RESULT': 'success', 'PR_NUMBER': '', 'CLOSED_PR_NUMBER': '7'}
        with patch.dict(os.environ, env), patch.object(handoff, 'request') as request:
            handoff.outcome()
        request.assert_called_once_with('outcome', {'case_id': env['CASE_ID'], 'pr_number': 7, 'status': 'closed'})
        self.pr['merged_at'] = '2026-11-27T00:00:00Z'
        with patch('publish.output') as output:
            report_publication(self.pub.open(self.artifact))
            output.assert_any_call('pr', 7)

    def test_go_quoted_example_is_accepted_in_generated_regression(self):
        self.pub.case['examples'] = ['secret fixture: "example.json"']
        result = json.loads(self.artifact.read_text())
        result['test'] = 'var example = ' + json.dumps(self.pub.case['examples'][0])
        self.artifact.write_text(json.dumps(result))
        self.assertEqual(self.pub.open(self.artifact)['number'], 7)

    def test_hosted_publisher_requires_a_fine_grained_token(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'PR_TOKEN': 'ghp_test_fixture'}):
            with self.assertRaisesRegex(ValueError, 'fine-grained'):
                Publisher(self.pub.case)

    def test_withdrawn_batch_never_reports_an_unchanged_proposal(self):
        self.pub.case['examples'] = []
        self.artifact.write_text('{"status":"unchanged","edits":[],"test":""}')
        with self.assertRaises(EvidenceWithdrawn):
            self.pub.open(self.artifact)
        self.assertEqual(self.creates, 0)

    def test_refresh_checks_the_original_base_but_allows_evidence_withdrawal(self):
        case = {**self.pub.case, 'repo': handoff.REPO, 'expected': 'No match for the target detector.'}
        env = {'EXPECTED_CASE': json.dumps(case), 'STAGING_SHA': 'b' * 40, 'TRIAL': 'false'}
        with patch.dict(os.environ, env), patch.object(handoff, 'request') as request, patch.object(handoff, 'output') as output:
            request.return_value = {'case': {**case, 'examples': []}}
            handoff.claim()
            output.assert_called_once_with('case', request.return_value['case'])
            request.return_value = {'case': {**case, 'base_sha': 'b' * 40}}
            with self.assertRaises(ValueError):
                handoff.claim()

    def test_second_case_can_publish_after_the_first_test_has_merged(self):
        first_path = self.pub.test
        self.baseline_files.add(first_path)
        next_case = {**self.pub.case, 'id': 'abcdef12-1234-1234-1234-123456789abc'}
        self.pub = Publisher(next_case)
        self.assertNotEqual(first_path, self.pub.test)
        self.assertEqual(Publisher(next_case).test, self.pub.test)
        self.status = {self.pub.source: 'modified', self.pub.test: 'added'}
        with patch.object(self.pub, 'remote', side_effect=self.github):
            self.assertEqual(self.pub.open(self.artifact)['number'], 7)

    def test_failed_confirmation_reports_retry_even_when_a_pr_exists(self):
        env = {'CASE_ID': self.pub.case['id'], 'PUBLISH_RESULT': 'failure', 'PR_NUMBER': '7', 'UNCHANGED': ''}
        with patch.dict(os.environ, env), patch.object(handoff, 'request') as request:
            handoff.outcome()
        request.assert_called_once_with('outcome', {'case_id': env['CASE_ID'], 'pr_number': None, 'status': 'retry'})

    def test_recovers_a_branch_created_with_the_legacy_filename(self):
        legacy = TARGETS[self.pub.case['detector'], self.pub.case['pattern']][1]
        self.status[legacy] = self.status.pop(self.pub.test)
        self.files[legacy] = self.files.pop(self.pub.test)
        self.ref = 'commit'
        self.assertEqual(self.pub.open(self.artifact)['number'], 7)

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
