import os
import time
import json
from PyQt6.QtCore import QObject, pyqtSignal, QTimer
import util 
from wallet import Wallet 


class Monitor(QObject):
    monitorStatus = pyqtSignal(str, str, str, str)

    def __init__(self, user, password, datadir, loglevel):
        super().__init__()
        self.user = user
        self.password = password
        self.datadir = datadir
        self.btcdir = f'{datadir}/btcd'
        self.walletsdir = f'{datadir}/wallets'
        self.loglevel = loglevel
        self.network = ''
        self.wallet_name = ''
        self.timer = QTimer()
        self.timer.setInterval(10000)
        self.timer.timeout.connect(self.run)
        self.timer.start()
        
    def monitor(self, network, wallet_name):
        self.network = network
        self.wallet_name = wallet_name
        self.network_param = f'--{network}' if network in ['simnet','testnet'] else ''
        self.port = list(filter(
            lambda w: w['name']==wallet_name, 
            util.get_wallets(self.walletsdir, self.network)))[0]['port']   
        self.wallet = Wallet(
            self.wallet_name, self.port, self.network, 
            self.user, self.password, self.walletsdir, self.loglevel)
        self.timer.timeout.emit()
        
    def stop(self):
        self.timer.stop()

    def run(self):
        if self.network:
            cmd = f'btcctl {self.network_param} --rpcuser={self.user} --rpcpass={self.password} getblockcount'
            o,e = util.run(cmd)  
            network_status = o
            balance,e = self.wallet.run('walletbalance')
            info,e = self.wallet.run('getinfo')
            peers,e = self.wallet.run('listpeers')
            channels,e = self.wallet.run('listchannels')
            wallet_status = ''
            try:
                j = {
                    'balance' : util.to_int(balance['total_balance']),
                    'pubkey' : info['identity_pubkey'],
                    'peers' : [util.Peer(p).__dict__ for p in peers['peers']],
                    'channels': [util.Channel(c).__dict__ for c in channels['channels']], 
                }
                wallet_status = json.dumps(j, indent=2)
                # print(wallet_status)
            except Exception as ex:
                print(ex)
                j = {}
            self.monitorStatus.emit(self.network, self.wallet_name, network_status, wallet_status)

