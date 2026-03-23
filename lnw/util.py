import requests
import subprocess
import json
import psutil

def run(cmd):
	p = subprocess.run(cmd.split(), capture_output=True, text=True)  
	return p.stdout.strip(), p.stderr.strip()

def to_int(s):
	try:
		return int(float(s))
	except:
		return 0

class Peer():
    def __init__(self, js):
        # print(js)
        self.pub_key = js['pub_key']
        self.address = js['address']
        self.sent = to_int(js['sat_sent'])
        self.recieved = to_int(js['sat_recv'])
    def __str__(self):
        return json.dumps(self.__dict__)

class Channel():
    def __init__(self, js):
        # print(js)
        # self.chan_id = js['chan_id']
        self.remote_pubkey = js['remote_pubkey']
        self.local_balance = to_int(js['local_balance'])
        self.remote_balance = to_int(js['remote_balance'])
        self.channel_point = js['channel_point']
        self.capacity = js['capacity']
        self.unsettled_balance = js['unsettled_balance']        
    def __str__(self):
        return json.dumps(self.__dict__)

def get_wallets(walletsdir, network):
    wallets = []
    try:
        print(f'{walletsdir}/{network}/wallets.json')
        with open(f'{walletsdir}/{network}/wallets.json') as r:
            js = json.loads(r.read())
            return js
    except Exception as ex:
        print(ex)
        return []


def is_process_running(processName):
    for proc in psutil.process_iter():
        try:
            if processName.lower() in proc.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False;

def is_btcd_running(network):
    for proc in psutil.process_iter():
        try:
            cmdline = proc.cmdline()
            if 'btcd' in cmdline:
                if ((network == 'mainnet' and '--simnet' not in cmdline and '--testnet' not in cmdline)
                    or f'--{network}' in cmdline):
                    return True
        except:
            pass
    return False;

def is_lnd_running(network, wallet_name):
    for proc in psutil.process_iter():
        try:
            cmdline = proc.cmdline()
            if ('lnd' in cmdline 
                and f'--bitcoin.{network}' in cmdline 
                and f'/wallets/{network}/{wallet_name}' in cmdline):
                print('#################### lnd is running')
                return True
        except:
            pass
    print('@@@@@@@@@@@@@@@@@@@@@@@@ lnd not running')
    return False;



url_blockcount = 'https://mempool.space/%sapi/blocks/tip/height'

def get_blockcount(network):
	if network == 'simnet':
		return 0
	if network == 'testnet':
		net = 'testnet/'
	else:
		net = ''
	url = url_blockcount % net
	r = requests.get(url)
	return to_int(r.text.strip())


