"""Fixed isolation evidence only; not an EJS task executor or dispatcher.

Invoke manually only on protected control main after independent review.
No arguments, manifest inputs, source checkouts or arbitrary commands accepted.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

IMAGE = 'docker.io/library/python@sha256:623674a14ef93d052bb9b0de4dbf5f28eb578a35263838941cc8aa43213c1487'
FIXTURE = """import socket
s=socket.socket();s.bind(('0.0.0.0',18080));s.listen(8)
while True:
 c,_=s.accept();c.sendall(b'SYNTHETIC_ONLY');c.close()
"""
TIMEOUT = """import subprocess,sys,time
p=subprocess.Popen([sys.executable,'-I','-B','-c','import time;time.sleep(60)'])
print('synthetic-child-started',flush=True)
p.wait()
"""
ROOT = Path(__file__).resolve().parent


def docker(*args, timeout=20):
    return subprocess.run(['docker', *args], capture_output=True, text=True, timeout=timeout, check=True)


def isolation_args():
    return ['--network','none','--user','65532:65532','--read-only',
            '--cap-drop','ALL','--security-opt','no-new-privileges',
            '--memory','128m','--memory-swap','128m','--cpus','0.5',
            '--pids-limit','32','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=16m',
            '--env','EJS_FINAL_SUBMIT=false','--env','EJS_KILL_SWITCH=true']


def require(condition):
    if not condition:
        raise ValueError('isolation assertion failed')


def verify_config(info):
    host, config = info['HostConfig'], info['Config']
    mounts = info['Mounts']
    require(host['NetworkMode'] == 'none' and not host.get('PortBindings'))
    require(host.get('PidMode', '') in ('', 'private'))
    require(host.get('IpcMode', 'private') == 'private')
    require(host.get('UTSMode', '') == '')
    require(host.get('CgroupnsMode', 'private') == 'private')
    require(not host.get('VolumesFrom') and not host.get('Links'))
    require(host['ReadonlyRootfs'] and not host['Privileged'] and not host.get('Devices'))
    require(config['User'] == '65532:65532')
    require(host['CapDrop'] == ['ALL'] and not host.get('CapAdd'))
    require('no-new-privileges' in host['SecurityOpt'])
    require(host['Memory'] == 134217728 and host['MemorySwap'] == 134217728)
    require(host['NanoCpus'] == 500000000 and host['PidsLimit'] == 32)
    require(set(host['Tmpfs']) == {'/tmp'})
    require(all(flag in host['Tmpfs']['/tmp'].split(',') for flag in ('noexec','nosuid','nodev','size=16m')))
    binds = [m for m in mounts if m['Type'] == 'bind']
    require(len(binds) == 2 and {m['Destination'] for m in binds} == {'/probe.py','/reviewed'})
    require(all(m['RW'] is False for m in binds))
    require(all(m['Type'] == 'bind' or (m['Type'] == 'tmpfs' and m['Destination'] == '/tmp') for m in mounts))
    require(config['Image'] == IMAGE)


def main():
    if len(sys.argv) != 1:
        raise ValueError('arguments forbidden')
    if (os.environ.get('GITHUB_REPOSITORY') != 'cagataybuyuk/ejs-test-control'
        or os.environ.get('GITHUB_REF') != 'refs/heads/main'
        or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
        or os.environ.get('GITHUB_RUN_ATTEMPT') != '1'):
        raise PermissionError('protected control main manual run required')
    sha = os.environ.get('GITHUB_SHA','')
    run_id = os.environ.get('GITHUB_RUN_ID','')
    if not re.fullmatch('[0-9a-f]{40}', sha) or not re.fullmatch('[0-9]+',run_id):
        raise ValueError('invalid control identity')
    # Workflow supplies these from GitHub context, never from dispatch inputs.
    # Effective branch/review protection is an external precondition, not proven
    # by environment strings; this program is never an approval verifier.
    prefix = 'ejs-proof-' + run_id
    fixture, task, timeout_task = (prefix+s for s in ('-fixture','-probe','-timeout'))
    started = time.monotonic()
    receipt = {'schema':'EJS-ISOLATION-RECEIPT-1','control_sha':sha,'run_id':run_id,
               'image':IMAGE,'task_execution_authorized':False,'ejs_source_executed':False,
               'status':'FAIL','checks':{}}
    try:
        # Network-enabled image preparation is explicitly outside offline proof.
        docker('pull', IMAGE, timeout=120)
        with tempfile.TemporaryDirectory(prefix='ejs-synthetic-') as folder:
            reviewed = Path(folder)/'reviewed'
            reviewed.mkdir(mode=0o755)
            (reviewed/'fixture.txt').write_text('SYNTHETIC_ONLY\n')
            (Path(folder)/'host-sentinel').write_text('SYNTHETIC_OUTSIDE_ONLY')
            docker('run','--detach','--name',fixture,'--read-only','--user','65532:65532',
                   '--cap-drop','ALL','--security-opt','no-new-privileges','--memory','64m',
                   '--memory-swap','64m','--cpus','0.25','--pids-limit','16',
                   IMAGE,'python','-I','-B','-c',FIXTURE)
            fixture_ready = False
            for _ in range(10):
                try:
                    docker('exec',fixture,'python','-I','-B','-c',
                           "import socket; s=socket.create_connection(('127.0.0.1',18080),1); assert s.recv(32)==b'SYNTHETIC_ONLY';s.close()")
                    fixture_ready = True
                    break
                except subprocess.CalledProcessError:
                    time.sleep(0.25)
            require(fixture_ready)
            network = json.loads(docker('inspect',fixture).stdout)[0]['NetworkSettings']['Networks']['bridge']
            address, gateway = network['IPAddress'], network['Gateway']
            require(ipaddress.ip_address(address).is_private and ipaddress.ip_address(gateway).is_private)
            common = isolation_args() + ['--mount',f'type=bind,src={ROOT / "probe.py"},dst=/probe.py,readonly',
                '--mount',f'type=bind,src={reviewed},dst=/reviewed,readonly',
                '--env',f'PROBE_FIXTURE_IPV4={address}','--env',f'PROBE_HOST_GATEWAY={gateway}']
            docker('create','--name',task,*common,IMAGE,'python','-I','-B','/probe.py')
            verify_config(json.loads(docker('inspect',task).stdout)[0])
            result = docker('start','--attach',task,timeout=30)
            state = json.loads(docker('inspect',task).stdout)[0]['State']
            require(state['ExitCode'] == 0 and not state['OOMKilled'])
            require(len(result.stdout.encode()) <= 4096)
            data = json.loads(result.stdout)
            require(data['schema'] == 'EJS-ISOLATION-PROBE-1')
            require(len(data['checks']) == 18 and all(v is True for v in data['checks'].values()))
            # Exercise bounded timeout and kill/reap of a container with a child.
            docker('create','--name',timeout_task,*common,IMAGE,'python','-I','-B','-c',TIMEOUT)
            verify_config(json.loads(docker('inspect',timeout_task).stdout)[0])
            try:
                docker('start','--attach',timeout_task,timeout=3)
                raise AssertionError('timeout not enforced')
            except subprocess.TimeoutExpired as exc:
                output = exc.stdout or b''
                require(b'synthetic-child-started' in (output.encode() if isinstance(output,str) else output))
                docker('kill',timeout_task)
                stopped = json.loads(docker('inspect',timeout_task).stdout)[0]['State']
                require(stopped['Running'] is False and stopped['Pid'] == 0)
            receipt['checks'] = {**data['checks'],'host_configuration_verified':True,
                                  'controlled_fixture_live':True,'timeout_descendants_reaped':True}
            receipt['probe_output_sha256'] = hashlib.sha256(result.stdout.encode()).hexdigest()
            receipt['status'] = 'PASS'
    finally:
        cleaned = True
        for name in (task,timeout_task,fixture):
            try:
                docker('rm','--force',name)
            except subprocess.CalledProcessError:
                # Missing containers are harmless; distinguish daemon failure.
                try:
                    docker('info', '--format','{{.ServerVersion}}')
                    names = docker('ps','--all','--format','{{.Names}}').stdout.splitlines()
                    cleaned = cleaned and name not in names
                except Exception:
                    cleaned = False
        receipt['cleanup_verified'] = cleaned
        if not cleaned:
            receipt['status'] = 'FAIL'
        receipt['elapsed_seconds'] = round(time.monotonic()-started,3)
        # Fixed technical booleans/digests only; never dump subprocess stderr/env.
        print(json.dumps(receipt,sort_keys=True))
    return 0 if receipt['status']=='PASS' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print('{"schema":"EJS-ISOLATION-RECEIPT-1","status":"FAIL","reason":"proof_failed","task_execution_authorized":false}')
        raise SystemExit(1)
