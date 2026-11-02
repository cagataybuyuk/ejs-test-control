import errno
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('proof_runner', ROOT/'proof/run_isolation_proof.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def config():
    return {'HostConfig':{'NetworkMode':'none','PortBindings':{},'ReadonlyRootfs':True,
        'Privileged':False,'Devices':[],'CapDrop':['ALL'],'CapAdd':[],
        'SecurityOpt':['no-new-privileges'],'Memory':134217728,'MemorySwap':134217728,
        'NanoCpus':500000000,'PidsLimit':32,'Tmpfs':{'/tmp':'rw,noexec,nosuid,nodev,size=16m'}},
        'Config':{'User':'65532:65532','Image':runner.IMAGE},
        'Mounts':[{'Destination':'/probe.py','Type':'bind','RW':False},
                  {'Destination':'/reviewed','Type':'bind','RW':False}]}


class IsolationContractTests(unittest.TestCase):
    def test_exact_configuration_and_optional_tmpfs_inspection(self):
        runner.verify_config(config())
        data=config()
        data['Mounts'].append({'Destination':'/tmp','Type':'tmpfs','RW':True})
        runner.verify_config(data)

    def test_dangerous_runtime_variants_are_rejected(self):
        variants=[('NetworkMode','host'),('PidMode','host'),('IpcMode','host'),('UTSMode','host'),
                  ('CgroupnsMode','host'),('VolumesFrom',['host-container']),('Links',['other:host']),('ReadonlyRootfs',False),('Privileged',True),
                  ('Devices',[{'PathOnHost':'synthetic-device'}]),('CapDrop',[]),
                  ('CapAdd',['SYS_ADMIN']),('SecurityOpt',[]),('Memory',0),('MemorySwap',-1),
                  ('NanoCpus',0),('PidsLimit',0),('PortBindings',{'1/tcp':[{}]}),
                  ('Tmpfs',{'/tmp':'rw,size=1g'}),('Tmpfs',{'/tmp':'rw,noexec,nosuid,nodev,size=16m','/host':'rw'})]
        for name,value in variants:
            with self.subTest(name=name):
                data=config();data['HostConfig'][name]=value
                with self.assertRaises((ValueError,KeyError)):
                    runner.verify_config(data)

    def test_root_user_wrong_image_rw_and_extra_host_mounts_rejected(self):
        for field,value in [('User','0'),('Image','python:latest')]:
            data=config();data['Config'][field]=value
            with self.assertRaises(ValueError): runner.verify_config(data)
        data=config();data['Mounts'][0]['RW']=True
        with self.assertRaises(ValueError): runner.verify_config(data)
        data=config();data['Mounts'].append({'Destination':'/host','Type':'bind','RW':False})
        with self.assertRaises(ValueError): runner.verify_config(data)

    def test_untrusted_context_never_invokes_docker(self):
        valid={'GITHUB_REPOSITORY':'cagataybuyuk/ejs-test-control','GITHUB_REF':'refs/heads/main',
               'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_RUN_ATTEMPT':'1',
               'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'123'}
        cases=[{}, {**valid,'GITHUB_REPOSITORY':'other/repo'},
               {**valid,'GITHUB_REF':'refs/heads/unreviewed'}, {**valid,'GITHUB_EVENT_NAME':'pull_request'},
               {**valid,'GITHUB_RUN_ATTEMPT':'2'}, {**valid,'GITHUB_SHA':'main'},
               {**valid,'GITHUB_RUN_ID':'123;echo unsafe'}]
        for env in cases:
            with self.subTest(env=env),patch.dict(runner.os.environ,env,clear=True),\
                patch.object(runner.sys,'argv',['run_isolation_proof.py']),patch.object(runner,'docker') as docker:
                with self.assertRaises((ValueError,PermissionError)): runner.main()
                docker.assert_not_called()

    def test_manifest_or_command_arguments_are_never_accepted(self):
        with patch.object(runner.sys,'argv',['runner','--task','secret_scan']),patch.object(runner,'docker') as docker:
            with self.assertRaises(ValueError): runner.main()
            docker.assert_not_called()

    def test_no_shell_and_fixed_image_digest(self):
        self.assertRegex(runner.IMAGE,r'^docker.io/library/python@sha256:[0-9a-f]{64}$')
        with patch.object(runner.subprocess,'run') as run:
            runner.docker('info')
            args,kwargs=run.call_args
            self.assertEqual(args[0],['docker','info'])
            self.assertFalse(kwargs.get('shell',False))
            self.assertTrue(kwargs['check'])
            self.assertLessEqual(kwargs['timeout'],20)

    def test_workflow_cannot_dispatch_from_pr_or_caller_input(self):
        workflow=(ROOT/'.github/workflows/control.yml').read_text()
        self.assertIn("github.ref == 'refs/heads/main'",workflow)
        self.assertIn("github.event_name == 'workflow_dispatch'",workflow)
        self.assertNotIn('inputs:',workflow)
        self.assertNotIn('secrets.',workflow)
        self.assertNotIn('pull_request_target',workflow)
        self.assertNotIn('self-hosted',workflow)
        self.assertIn('persist-credentials: false',workflow)
        self.assertIn('runs-on: ubuntu-24.04',workflow)

    def test_connection_refusal_is_not_mistaken_for_network_denial(self):
        probe_spec=importlib.util.spec_from_file_location('synthetic_probe',ROOT/'proof/probe.py')
        probe=importlib.util.module_from_spec(probe_spec)
        probe_spec.loader.exec_module(probe)
        for code,expected in [(errno.ENETUNREACH,True),(errno.EHOSTUNREACH,True),
                              (errno.ECONNREFUSED,False),(errno.ETIMEDOUT,False)]:
            with self.subTest(code=code),patch.object(probe.socket,'socket') as sock:
                sock.return_value.__enter__.return_value.connect.side_effect=OSError(code,'synthetic')
                self.assertEqual(probe.network_denied('192.0.2.1',18080,probe.socket.AF_INET),expected)


if __name__=='__main__': unittest.main()
