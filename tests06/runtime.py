import json,os,platform,sqlite3,subprocess,sys
import Crypto,cryptography
print(json.dumps({'python':sys.version,'node':subprocess.check_output(['node','--version'],text=True).strip(),'pycryptodome':Crypto.__version__,'cryptography':cryptography.__version__,'sqlite':sqlite3.sqlite_version,'platform':platform.platform(),'machine':platform.machine(),'visible_cpus':os.cpu_count(),'cpuinfo':open('/proc/cpuinfo').read().split('\n\n')[0]},indent=2))
