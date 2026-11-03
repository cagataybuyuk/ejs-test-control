"""Actual Git operations only in disposable local repositories, never GitHub.

These tests prove selected local Git behaviors, not real remote authorization,
GitHub API atomicity/permissions or a safe ledger writer. No task is spawned.
"""
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest

REF='refs/heads/gd005-synthetic-ledger'
IDENTITY='00000000-0000-4000-8000-000000000001'


@unittest.skipUnless(shutil.which('git'),'Git required for local fixture proof')
class LocalGitLedgerFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ejs-local-ledger-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.origin=self.root/'origin.git'
        self.writer=self.root/'writer.git'
        # No host credentials, git hooks or global/system configuration inherited.
        self.env={
            'PATH':os.environ.get('PATH',''), 'LC_ALL':'C',
            'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,
            'GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_COUNT':'0',
            'GIT_AUTHOR_NAME':'EJS Synthetic','GIT_AUTHOR_EMAIL':'synthetic@example.invalid',
            'GIT_COMMITTER_NAME':'EJS Synthetic','GIT_COMMITTER_EMAIL':'synthetic@example.invalid',
            'GIT_AUTHOR_DATE':'2026-11-03T00:00:00Z','GIT_COMMITTER_DATE':'2026-11-03T00:00:00Z',
        }
        for repo in (self.origin,self.writer):
            self.git(None,'init','--bare','--initial-branch=synthetic',str(repo))
        self.git(self.origin,'config','receive.denyNonFastForwards','true')
        self.git(self.origin,'config','receive.denyDeletes','true')
        self.initial=self.commit({'revision':0,'state':'available','authorization_id':IDENTITY})
        self.push(self.initial)

    def git(self,repo,*args,input=None,check=True):
        command=['git','-c','core.hooksPath='+os.devnull,
                 '-c','protocol.allow=never','-c','protocol.file.allow=always']
        if repo is not None:
            # This helper cannot target a host worktree or a remote repository.
            if repo.resolve() not in (self.origin,self.writer):
                raise ValueError('outside synthetic fixture')
            command+=['--git-dir',str(repo)]
        return subprocess.run(command+list(args),input=input,capture_output=True,text=True,
                              timeout=10,check=check,env=self.env,cwd=self.root)

    def commit(self,state,parent=None):
        blob=self.git(self.writer,'hash-object','-w','--stdin',input=json.dumps(state,sort_keys=True)).stdout.strip()
        tree=self.git(self.writer,'mktree',input=f'100644 blob {blob}\tstate.json\n').stdout.strip()
        args=['commit-tree',tree,'-m','SYNTHETIC_ONLY']
        if parent: args+=['-p',parent]
        return self.git(self.writer,*args).stdout.strip()

    def push(self,commit,check=True,force=False):
        args=['push','--porcelain']
        if force: args.append('--force')
        return self.git(self.writer,*args,str(self.origin),commit+':'+REF,check=check)

    def head(self):
        return self.git(self.origin,'rev-parse',REF).stdout.strip()

    def state(self):
        return json.loads(self.git(self.origin,'show',REF+':state.json').stdout)

    def candidate(self,state,nonce,parent=None,**extra):
        return self.commit({'revision':1,'state':state,'authorization_id':IDENTITY,
                            'claim_nonce':nonce,**extra},parent or self.initial)

    def test_two_distinct_claims_from_one_parent_have_one_local_winner(self):
        left=self.candidate('consumed','synthetic-left')
        right=self.candidate('consumed','synthetic-right')
        barrier=threading.Barrier(2)
        def contender(commit):
            barrier.wait(timeout=5)
            return commit,self.push(commit,check=False).returncode
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(contender,c) for c in (left,right)]
            results=[f.result(timeout=15) for f in futures]
        winners=[commit for commit,code in results if code==0]
        self.assertEqual(len(winners),1,results)
        self.assertEqual(self.head(),winners[0])
        self.assertEqual(self.state()['state'],'consumed')

    def test_revoke_committed_first_rejects_stale_claim(self):
        revoked=self.candidate('revoked','synthetic-revoke')
        stale=self.candidate('consumed','synthetic-claim')
        self.push(revoked)
        self.assertNotEqual(self.push(stale,check=False).returncode,0)
        self.assertEqual(self.head(),revoked)
        self.assertEqual(self.state()['state'],'revoked')

    def test_claim_first_requires_revoke_rebased_on_consumed_state(self):
        claimed=self.candidate('consumed','synthetic-claim')
        stale_revoke=self.candidate('revoked','synthetic-revoke')
        self.push(claimed)
        self.assertNotEqual(self.push(stale_revoke,check=False).returncode,0)
        cancellation=self.commit({'revision':2,'state':'consumed','authorization_id':IDENTITY,
            'claim_nonce':'synthetic-claim','cancelled':True},parent=claimed)
        self.push(cancellation)
        self.assertEqual(self.state()['state'],'consumed')
        self.assertTrue(self.state()['cancelled'])

    def test_repeated_identical_push_can_succeed_without_a_fresh_claim(self):
        # Critical limitation: zero exit/HTTP success alone is NOT new admission.
        claimed=self.candidate('consumed','synthetic-same-process')
        first=self.push(claimed)
        again=self.push(claimed)
        self.assertEqual(first.returncode,0)
        self.assertEqual(again.returncode,0)
        self.assertIn('[up to date]',again.stdout)
        self.assertEqual(self.head(),claimed)
        self.assertEqual(self.state()['state'],'consumed')

    def test_force_rewind_and_deletion_denied_by_fixture_server_settings(self):
        claimed=self.candidate('consumed','synthetic-claim')
        self.push(claimed)
        self.assertNotEqual(self.push(self.initial,check=False,force=True).returncode,0)
        deletion=self.git(self.writer,'push','--porcelain',str(self.origin),':'+REF,check=False)
        self.assertNotEqual(deletion.returncode,0)
        self.assertEqual(self.head(),claimed)

    def test_graph_fast_forward_does_not_validate_business_state(self):
        # Demonstrate an UNSOLVED gate, rather than pretending Git enforces it.
        claimed=self.candidate('consumed','synthetic-claim')
        self.push(claimed)
        illicit=self.commit({'revision':2,'state':'available','authorization_id':IDENTITY},parent=claimed)
        accepted_by_git=self.push(illicit)
        self.assertEqual(accepted_by_git.returncode,0)
        self.assertEqual(self.state()['state'],'available')
        # Therefore trusted state validation + writer permissions are mandatory.

    def test_local_expected_old_update_ref_rejects_a_stale_writer(self):
        left=self.candidate('consumed','synthetic-left')
        right=self.candidate('consumed','synthetic-right')
        # Transfer candidate objects through isolated synthetic refs, not network.
        for commit in (left,right):
            self.git(self.writer,'push',str(self.origin),commit+':refs/heads/objects-'+commit)
        self.git(self.origin,'update-ref',REF,left,self.initial)
        stale=self.git(self.origin,'update-ref',REF,right,self.initial,check=False)
        self.assertNotEqual(stale.returncode,0)
        self.assertEqual(self.head(),left)
        # GitHub PATCH refs has no equivalent expected-old argument: not proven here.


if __name__=='__main__': unittest.main()
