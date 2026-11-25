#!/usr/bin/env python3
"""Check the ticket references in a commit message.

"issue: <id>" is a Redmine ticket and is checked by the shared Redmine script.
"NVBug: <id>" is an NVBugs bug and is checked here. The two trackers use
overlapping numbers, so the keyword decides which tracker a number belongs to.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

REDMINE_SCRIPT = ('/hpc/local/inst/hpc-internal-tools/tools/git_tools/git_redmine/'
                  'update_redmine_from_git_commit_python3.py')
REDMINE_PROJECT_ID = '9'
NVBUGS_GET_BUG = ('https://prod.api.nvidia.com/int/nvbugs/api/Bug/GetBug/{}'
                  '?includeDescriptionPlainTextReadOnly=false')
NVBUGS_MODULE = 'NET-SW-VMA'
# NVBugs ids are 32-bit; GetBug answers a larger number with HTTP 500.
NVBUG_ID_MAX = 2**31 - 1

# Same pattern the Redmine script matches, line by line.
REDMINE_RE = re.compile(r'issue\s*:\s*(\d+|None)', re.IGNORECASE)
NVBUG_RE = re.compile(r'\bnvbug[ \t]*:[ \t]*(\d+(?:[ \t]*,[ \t]*\d+)*)', re.IGNORECASE)
NVBUG_LOOKALIKE_RE = re.compile(r'\bnv[ \t]*bugs?[ \t]*[:#]?[ \t]*#?[ \t]*\d+', re.IGNORECASE)

FORMATS = ('  issue: <Redmine id>   tasks, feature requests and older bugs (Redmine)\n'
           '  NVBug: <NVBugs id>    bugs tracked in NVBugs')


def read_commit_message(commit):
    result = subprocess.run(['git', 'show', '-s', '--format=%B', commit],
                            capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit('ERROR: cannot read commit {}: {}'.format(commit, result.stderr.strip()))
    return result.stdout


def find_nvbug_ids(message):
    ids = []
    for match in NVBUG_RE.finditer(message):
        ids += [int(i) for i in re.split(r'[ \t]*,[ \t]*', match.group(1))]
    return list(dict.fromkeys(ids))


def find_lookalikes(message):
    return [m.group(0) for m in NVBUG_LOOKALIKE_RE.finditer(NVBUG_RE.sub('', message))]


def has_redmine_reference(message):
    return any(REDMINE_RE.search(line) for line in message.splitlines())


def get_bug(bug_id, token):
    """Return (bug, None) on success or (None, reason) on failure."""
    request = urllib.request.Request(NVBUGS_GET_BUG.format(bug_id), headers={
        'Authorization': 'Bearer ' + token, 'Accept': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read()
    except urllib.error.HTTPError as err:
        body = err.read()
    except OSError as err:
        return None, 'NVBugs is unreachable ({}); retry with bot:rm:retest'.format(err)
    try:
        reply = json.loads(body)
    except ValueError:
        reply = None
    if not isinstance(reply, dict):
        return None, 'NVBugs sent an unexpected answer; retry with bot:rm:retest'

    # The API gateway reports its own failures in this shape. A missing or
    # refused token comes back as HTTP 400 with "status": 401.
    if reply.get('successful') is False:
        status = reply.get('status')
        if status in (401, 403):
            return None, 'NVBugs refused the token (status {}); check the NVBUGS_TOKEN ' \
                         'credential'.format(status)
        if isinstance(status, int) and status >= 500:
            return None, 'NVBugs failed (status {}); retry with bot:rm:retest'.format(status)
        return None, 'NVBugs rejected the request: {}'.format(reply.get('response'))

    bug = reply.get('ReturnValue')
    if reply.get('IsSuccess') and isinstance(bug, dict):
        return bug, None
    error = (reply.get('ErrorMessage') or 'no details').splitlines()[0][:200]
    return None, 'not found or not visible to the CI account ({})'.format(error)


def check_nvbugs(bug_ids):
    token = os.environ.get('NVBUGS_TOKEN')
    if not token:
        print('ERROR: the commit references NVBugs, but NVBUGS_TOKEN is not set for this job')
        return False
    ok = True
    for bug_id in bug_ids:
        if bug_id > NVBUG_ID_MAX:
            bug, error = None, 'not a valid NVBugs id'
        else:
            bug, error = get_bug(bug_id, token)
        if error:
            print('ERROR: NVBug {}: {}'.format(bug_id, error))
            ok = False
            continue
        module = (bug.get('ModuleInfo') or {}).get('Value') or 'unknown'
        action = (bug.get('BugAction') or {}).get('Value') or 'unknown'
        print('NVBug {}: {} [module: {}, {}]'.format(bug_id, bug.get('Synopsis'), module, action))
        if module.lower() != NVBUGS_MODULE.lower():
            print('WARNING: NVBug {} is in module {}, not {}'.format(bug_id, module, NVBUGS_MODULE))
    return ok


def run_redmine_check(commit, pr_url):
    cmd = [sys.executable, REDMINE_SCRIPT, '--update', '--project_id=' + REDMINE_PROJECT_ID,
           '--on_issue_not_in_project=fail', '--commit_id=' + commit]
    if pr_url:
        cmd.append('--pr_url=' + pr_url)
    sys.stdout.flush()
    return subprocess.call(cmd) == 0


def main():
    parser = argparse.ArgumentParser(description='Check the ticket references in a commit message.')
    parser.add_argument('--commit-id', default=os.environ.get('ghprbActualCommit') or 'HEAD')
    parser.add_argument('--pr-url', default=os.environ.get('ghprbPullLink'))
    parser.add_argument('--dry-run', action='store_true',
                        help='only parse the message; do not contact NVBugs or Redmine')
    args = parser.parse_args()

    message = read_commit_message(args.commit_id)
    bug_ids = find_nvbug_ids(message)
    redmine = has_redmine_reference(message)

    for text in find_lookalikes(message):
        print('WARNING: "{}" is not an NVBugs reference; write "NVBug: <id>"'.format(text.strip()))
    print('Commit {}: Redmine reference: {}, NVBugs references: {}'.format(
        args.commit_id, 'yes' if redmine else 'no', ', '.join(map(str, bug_ids)) or 'none'))
    if not bug_ids and not redmine:
        print('ERROR: no ticket reference found. Add a line with one of:\n' + FORMATS)
        return 1
    if args.dry_run:
        return 0

    ok = check_nvbugs(bug_ids) if bug_ids else True
    if redmine:
        ok = run_redmine_check(args.commit_id, args.pr_url) and ok
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
