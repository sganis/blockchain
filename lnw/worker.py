import os
import json
import time
import subprocess
from PyQt6.QtCore import QObject, pyqtSignal
from wallet import Wallet
import util 


class Worker(QObject):
    runBtcdDone = pyqtSignal(str)
    stopBtcdDone = pyqtSignal(str)
    stopWalletDone = pyqtSignal(str)
    changeNetworkDone = pyqtSignal(str)
    changeWalletDone = pyqtSignal(str, str)
    createDone = pyqtSignal(str, str)
    unlockDone = pyqtSignal(str)
    connectDone = pyqtSignal(str)
    channelDone = pyqtSignal(str)
    closeChannelDone = pyqtSignal(str)
    invoiceDone = pyqtSignal(str, str)
    payDone = pyqtSignal(str, str)
    progress = pyqtSignal(str)
    mineDone = pyqtSignal(str, str)

    def __init__(self, user, password, datadir, loglevel):
        super().__init__()
        self.user = user
        self.password = password
        self.datadir = datadir
        self.btcdir = f'{datadir}/btcd'
        self.walletsdir = f'{datadir}/wallets'
        self.loglevel = loglevel
        self.btcd_process = None
        self.wallet = None
        self.wallets = {}
        self.port = 10000

    def gektTotalBlockcount(self):
        return util.get_blockcount(self.network)

    def runBtcd(self):        
        cmd = f'btcd --txindex {self.network_param}'
        cmd = f'{cmd} --rpcuser={self.user} --rpcpass={self.password} '
        cmd = f'{cmd} --datadir={self.btcdir}/data --logdir={self.btcdir}/logs '
        cmd = f'{cmd} --configfile={self.btcdir}/btcd.conf --debuglevel={self.loglevel}'
        miningaddr_file = f'{self.walletsdir}/{self.network}/alice/address.txt'
        if self.network == 'simnet' and os.path.exists(miningaddr_file):
            with open(miningaddr_file) as r:
                miningaddr = r.read().strip()
            cmd = f'{cmd} --miningaddr={miningaddr}'
        print(cmd)
        self.btcd_process = subprocess.Popen(cmd.split())
        self._monitor_btcd()
        self.progress.emit('Btcd started.')
    
    def stopBtcd(self):
        if self.btcd_process:
            self.btcd_process.terminate()
            self.btcd_process.wait()
            self.progress.emit('Btcd stopped.')

    def getBlockcount(self):
        cmd = f'btcctl {self.network_param} --rpcuser={self.user} --rpcpass={self.password} getblockcount'
        o,e = util.run(cmd)
        return util.to_int(o)

    def _monitor_btcd(self):
        # check until rpc server responds
        cmd = f'btcctl {self.network_param} --rpcuser={self.user} --rpcpass={self.password} getinfo'
        o, e = util.run(cmd)

        while not o:
            self.progress.emit(f'Btcd is starting in {self.network}...')
            print(f'###### btcd getinfo stderr: {e}')
            time.sleep(10)            
            o,e = util.run(cmd)
        print(f'###### btcd getinfo stdout: {o}')
        percent = 0
        blocks = self.getBlockcount()
        total_blocks = util.get_blockcount(self.network)
        if total_blocks > 0:
            percent = int(blocks/total_blocks*100.0)
        print(f'sync status: {percent}%, blocks: {blocks}/{total_blocks}')
        
    def changeNetwork(self, network):
        self.network = network
        self.network_param = f'--{network}' if network in ['simnet','testnet'] else ''

        if network == 'simnet' and not util.is_btcd_running(network):
            # run and create alice wallet
            self.runBtcd()    
            # self.stopBtcd()
        else:
            self.runBtcd()
            # self.stopWallet()
        self.changeNetworkDone.emit(network)

    def changeWallet(self, wallet_name):
        # self.stopWallet()
        self.wallet_name = wallet_name
        self.port = list(filter(
            lambda w: w['name']==wallet_name, 
            util.get_wallets(self.walletsdir, self.network)))[0]['port']    

        wallet_id = f'{self.network}/{wallet_name}'

        if wallet_id not in self.wallets:
            self.wallets[wallet_id] = Wallet(
                self.wallet_name, self.port, self.network, 
                self.user, self.password, self.walletsdir, self.loglevel)
        
        self.wallet = self.wallets[wallet_id]
        
        if not self.wallet.is_running():
            self.wallet.start()

        self.changeWalletDone.emit(wallet_name, self._get_status())

    def stopWallet(self):
        if self.wallet:
            self.wallet.stop()
            self.stopWalletDone.emit(self.wallet_name)

    def _get_max_port(self):
        try:
            with open(f'{self.walletsdir}/{self.network}/wallets.json') as r:
                js = json.loads(r.read())
                return max([w['port'] for w in js])
        except:
            pass
        return 10000

    def create(self, wallet_name, password):
        # self.stopWallet()
        self.port = self._get_max_port() + 1
        self.wallet_name = wallet_name
        wallet_id = f'{self.network}/{self.wallet_name}'
        
        if wallet_id not in self.wallets:
            self.wallets[wallet_id] = Wallet(
                self.wallet_name, self.port, self.network, 
                self.user, self.password, self.walletsdir, self.loglevel)
        
        self.wallet = self.wallets[wallet_id]
        self.wallet.start()
        o = self.wallet.create(password)
        
        if o == 'OK':
            self.wallet.monitor()
            js, e = self.wallet.run('newaddress p2wkh')
            
            if js:
                with open(f'{self.wallet.dir}/address.txt', 'wt') as w:
                    w.write(js['address'])   
                js = []
                
                if os.path.exists(f'{self.walletsdir}/{self.network}/wallets.json'):
                    try:
                        with open(f'{self.walletsdir}/{self.network}/wallets.json') as r:
                            js = json.loads(r.read())
                    except:
                        pass
                js.append({'name': wallet_name, 'port': self.port})
               
                if not os.path.exists(f'{self.walletsdir}/{self.network}'):
                    os.mkdir(f'{self.walletsdir}/{self.network}')
                
                with open(f'{self.walletsdir}/{self.network}/wallets.json', 'wt') as w:
                    w.write(json.dumps(js))

        self.createDone.emit(wallet_name, o)

    def _get_status(self):
        js,e = self.wallet.monitor()        
        message = ''

        if 'state' not in js:
            message = e
        
        elif js['state'] == 'RPC_ACTIVE':
            # get balance and info
            js,e = self.wallet.run('walletbalance')
            balance = js['total_balance']
            js,e = self.wallet.run('getinfo')
            pubkey = js['identity_pubkey']
            channels = js['num_active_channels']
            num_peers = js['num_peers']
            network = js['chains'][0]['network']
            message = f'balance: {balance}\npubkey: {pubkey}\nchannels: {channels}\nnum_peers: {num_peers}\nnetwork: {network}\n'
        else:
            message = str(js['state'])
        return message

    def unlock(self, password):
        print('unlocking....')
        o = self.wallet.unlock(password)
        self.unlockDone.emit(o)

    def connect(self, node_url):
        error = self.wallet.connect(node_url)
        self.connectDone.emit(error)

    def channel(self, node_key, local_amount, remote_amount):
        error = self.wallet.channel(node_key, local_amount, remote_amount)
        self.channelDone.emit(error)

    def closeChannel(self, channel_point):
        error = self.wallet.close_channel(channel_point)
        self.closeChannelDone.emit(error)

    def invoice(self, amount):
        o,e = self.wallet.invoice(amount)
        self.invoiceDone.emit(json.dumps(o, indent=2), e)

    def pay(self, pay_req):
        print(f'###################### pay req: {pay_req}')
        o,e = self.wallet.pay(pay_req)
        print(o)
        print(e)
        self.payDone.emit(json.dumps(o, indent=2), e)