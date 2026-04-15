import subprocess
import json
import datetime
 
results = {}
results['date'] = str(datetime.datetime.now())
 
out = subprocess.getoutput('ss -tuln')
results['ports'] = out
 
f2b = subprocess.getoutput('systemctl is-active fail2ban')
results['fail2ban'] = f2b
 
ssh = subprocess.getoutput('grep PermitRootLogin /etc/ssh/sshd_config')
results['ssh_root'] = ssh
 
with open('audit_report.json', 'w') as f:
    json.dump(results, f, indent=2)
 
print('Audit termine - audit_report.json cree')
