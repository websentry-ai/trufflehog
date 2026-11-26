"""Claim or report one case without echoing backend responses or authentication headers."""

import json
import os
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, Request
from uuid import UUID

from target import REPO, TARGETS


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def output(name, value):
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
        stream.write(f'{name}={json.dumps(value, separators=(",", ":"), ensure_ascii=True)}\n')


def request(operation, data):
    origin = urlsplit(os.environ['BACKEND_ORIGIN'])
    if origin.scheme != 'https' or not origin.hostname or origin.username or origin.password or origin.query or origin.fragment or origin.path.strip('/'):
        raise ValueError('Expected a staging HTTPS origin')
    data['run_id'] = os.environ['RUN_KEY']
    url = f'{origin.scheme}://{origin.netloc}/api/v1/dlp-enhancer/{REPO}/{operation}/'
    req = Request(url, data=json.dumps(data).encode(), headers={
        'Content-Type': 'application/json', 'Authorization': 'Bearer ' + os.environ['BACKEND_TOKEN']})
    for attempt in range(4):
        try:
            with build_opener(NoRedirect()).open(req, timeout=30) as response:
                return json.loads(response.read(8193))
        except HTTPError as error:
            if error.code not in {429, 500, 502, 503, 504} or attempt == 3:
                raise
        except (URLError, TimeoutError):
            if attempt == 3:
                raise
        time.sleep(2 ** attempt)


def claim():
    case = request('claim', {'base_sha': os.environ['STAGING_SHA'], 'synthetic_trial': os.environ['TRIAL'] == 'true'})['case']
    if case:
        if set(case) != {'id', 'base_sha', 'examples', 'detector', 'pattern', 'repo', 'expected'}:
            raise ValueError
        if (str(UUID(case['id'])) != case['id'] or case['repo'] != REPO or
                (case['detector'], case['pattern']) not in TARGETS or not re.fullmatch('[0-9a-f]{40}', case['base_sha']) or
                case['expected'] != 'No match for the target detector.' or not isinstance(case['examples'], list) or
                len(case['examples']) > 3 or not all(isinstance(e, str) and 0 < len(e) <= 256 for e in case['examples'])):
            raise ValueError
    output('case', case)


if __name__ == '__main__':
    try:
        if sys.argv[1] == 'claim':
            claim()
        elif sys.argv[1] == 'outcome':
            pr = os.environ.get('PR_NUMBER')
            request('outcome', {'case_id': os.environ['CASE_ID'], 'pr_number': int(pr) if pr else None,
                                'status': 'published' if pr else os.environ.get('STATUS') or 'retry'})
        else:
            raise ValueError
    except Exception:
        sys.exit('Backend handoff failed.')
