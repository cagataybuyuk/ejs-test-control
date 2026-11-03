"""Bounded cleanup of only this run's synthetic containers."""
import os
import re
import subprocess
import sys

run_id=os.environ.get('GITHUB_RUN_ID','')
if not re.fullmatch('[0-9]+',run_id) or os.environ.get('GITHUB_REPOSITORY')!='cagataybuyuk/ejs-test-control':
    raise SystemExit(2)
names=['ejs-proof-'+run_id+suffix for suffix in ('-probe','-timeout','-fixture')]
for name in names:
    subprocess.run(['docker','rm','--force',name],capture_output=True,timeout=15,check=False)
remaining=subprocess.run(['docker','ps','--all','--format','{{.Names}}'],capture_output=True,text=True,timeout=15,check=True).stdout.splitlines()
clean=not any(name in remaining for name in names)
print('synthetic-container-cleanup: '+('PASS' if clean else 'FAIL'))
raise SystemExit(0 if clean else 1)
