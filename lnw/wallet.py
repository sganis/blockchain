import os
import subprocess
import time
import json
import wexpect
import util

class Wallet():
    """
        getinfo          Returns basic information related to the active daemon.
        getrecoveryinfo  Display information about an ongoing recovery attempt.
        debuglevel       Set the debug level.
        stop             Stop and shutdown the daemon.
        version          Display lncli and lnd version info.
        sendcustom       
        subscribecustom  
        help, h          Shows a list of commands or help for one command

        Autopilot:
        autopilot  Interact with a running autopilot.

        Channels:
        openchannel        Open a channel to a node or an existing peer.
        batchopenchannel   Open multiple channels to existing peers in a single transaction.
        closechannel       Close an existing channel.
        closeallchannels   Close all existing channels.
        abandonchannel     Abandons an existing channel.
        channelbalance     Returns the sum of the total available channel balance across all open channels.
        pendingchannels    Display information pertaining to pending channels.
        listchannels       List all open channels.
        closedchannels     List all closed channels.
        getnetworkinfo     Get statistical information about the current state of the network.
        feereport          Display the current fee policies of all active channels.
        updatechanpolicy   Update the channel policy for all channels, or a single channel.
        exportchanbackup   Obtain a static channel back up for a selected channels, or all known channels.
        verifychanbackup   Verify an existing channel backup.
        restorechanbackup  Restore an existing single or multi-channel static channel backup.
        listaliases        List all aliases.
        updatechanstatus   Set the status of an existing channel on the network.

        Graph:
        describegraph   Describe the network graph.
        getnodemetrics  Get node metrics.
        getchaninfo     Get the state of a channel.
        getnodeinfo     Get information on a specific node.

        Invoices:
        addinvoice      Add a new invoice.
        lookupinvoice   Lookup an existing invoice by its payment hash.
        listinvoices    List all invoices currently stored within the database. Any active debug invoices are ignored.
        decodepayreq    Decode a payment request.
        cancelinvoice   Cancels a (hold) invoice.
        addholdinvoice  Add a new hold invoice.
        settleinvoice   Reveal a preimage and use it to settle the corresponding invoice.

        Macaroons:
        bakemacaroon       Bakes a new macaroon with the provided list of permissions and restrictions.
        listmacaroonids    List all macaroons root key IDs in use.
        deletemacaroonid   Delete a specific macaroon ID.
        listpermissions    Lists all RPC method URIs and the macaroon permissions they require to be invoked.
        printmacaroon      Print the content of a macaroon in a human readable format.
        constrainmacaroon  Adds one or more restriction(s) to an existing macaroon

        Mission Control:
        querymc    Query the internal mission control state.
        queryprob  Estimate a success probability.
        resetmc    Reset internal mission control state.
        getmccfg   Display mission control's config.
        setmccfg   Set mission control's config.

        Neutrino:
        neutrino  Interact with a running neutrino instance.

        On-chain:
        estimatefee    Get fee estimates for sending bitcoin on-chain to multiple addresses.
        sendmany       Send bitcoin on-chain to multiple addresses.
        sendcoins      Send bitcoin on-chain to an address.
        listunspent    List utxos available for spending.
        listchaintxns  List transactions from the wallet.

        Payments:
        sendpayment     Send a payment over lightning.
        payinvoice      Pay an invoice over lightning.
        sendtoroute     Send a payment over a predefined route.
        listpayments    List all outgoing payments.
        queryroutes     Query a route to a destination.
        fwdinghistory   Query the history of all forwarded HTLCs.
        trackpayment    Track progress of an existing payment.
        deletepayments  Delete a single or multiple payments from the database.
        importmc        Import a result to the internal mission control state.
        buildroute      Build a route from a list of hop pubkeys.

        Peers:
        connect     Connect to a remote lnd peer.
        disconnect  Disconnect a remote lnd peer identified by public key.
        listpeers   List all active, currently connected peers.
        peers       Interacts with the other nodes of the newtwork

        Profiles:
        profile  Create and manage lncli profiles.

        Startup:
        create           Initialize a wallet when starting lnd for the first time.
        createwatchonly  Initialize a watch-only wallet after starting lnd for the first time.
        unlock           Unlock an encrypted wallet at startup.
        changepassword   Change an encrypted wallet's password at startup.
        state            Get the current state of the wallet and RPC

        Wallet:
        newaddress     Generates a new address.
        walletbalance  Compute and display the wallet's current balance.
        signmessage    Sign a message with the node's private key.
        verifymessage  Verify a message signed with the signature.
        wallet         Interact with the wallet.

        Watchtower:
        tower     Interact with the watchtower.
        wtclient  Interact with the watchtower client.

        GLOBAL OPTIONS:
        --rpcserver value          The host:port of LN daemon. (default: "localhost:10009")
        --lnddir value             The path to lnd's base directory. (default: "C:\\Users\\San\\AppData\\Local\\Lnd")
        --socksproxy value         The host:port of a SOCKS proxy through which all connections to the LN daemon will be established over.
        --tlscertpath value        The path to lnd's TLS certificate. (default: "C:\\Users\\San\\AppData\\Local\\Lnd\\tls.cert")
        --chain value, -c value    The chain lnd is running on, e.g. bitcoin. (default: "bitcoin")
        --network value, -n value  The network lnd is running on, e.g. mainnet, testnet, etc. (default: "mainnet")
        --no-macaroons             Disable macaroon authentication.
        --macaroonpath value       The path to macaroon file.
        --macaroontimeout value    Anti-replay macaroon validity time in seconds. (default: 60)
        --macaroonip value         If set, lock macaroon to specific IP address.
        --profile value, -p value  Instead of reading settings from command line parameters or using the default profile, use a specific profile. If a default profile is set, this flag can be set to an empty string to disable reading values from the profiles file.
        --macfromjar value         Use this macaroon from the profile's macaroon jar instead of the default one. Can only be used if profiles are defined.
        --help, -h                 show help
        --version, -v              print the version
    """
    def __init__(self, wallet_name, port, network, user, password, folder, loglevel):
        self.wallet_name = wallet_name
        self.port = port # rpclisten=10001, listen=10011, restlisten=8001 
        self.network = network
        self.user = user
        self.password = password
        self.loglevel = loglevel
        self.dir = f'{folder}/{self.network}/{self.wallet_name}'
        self.process = None
        self.cmd = f'C:/Users/San/go/bin/lncli.exe'
        self.cmd = f'{self.cmd} --rpcserver=localhost:{self.port}'
        self.cmd = f'{self.cmd} --macaroonpath={self.dir}/data/chain/bitcoin/{self.network}/admin.macaroon'
        self.cmd = f'{self.cmd} --lnddir={self.dir}'

    def start(self):
        cmd = f'lnd --rpclisten=localhost:{self.port}'      # default: 10009
        cmd = f'{cmd} --listen=localhost:{self.port+10}'    # default: 9735
        cmd = f'{cmd} --restlisten=0'                       # default: 8080
        cmd = f'{cmd} --bitcoin.active'
        cmd = f'{cmd} --debuglevel={self.loglevel}'
        cmd = f'{cmd} --bitcoin.{self.network}'
        cmd = f'{cmd} --lnddir={self.dir}'
        
        # neutrino mode
        cmd = f'{cmd} --bitcoin.node=neutrino'
        cmd = f'{cmd} --neutrino.connect=localhost'
        # cmd = f'{cmd} --neutrino.addpeer=mainnet3-btcd.zaphq.io --neutrino.addpeer=mainnet4-btcd.zaphq.io --neutrino.useragentname=zap-desktop --neutrino.useragentversion=0.7.2-beta'
        
        # full node        
        # cmd = f'{cmd} --btcd.rpcuser={self.user} --btcd.rpcpass={self.password}'
        print(cmd)
        self.process = subprocess.Popen(cmd.split())
        
    def stop(self):
        self.process.terminate()
        self.process.wait()
        print(f'wallet terminated: {self.process}')

    def is_running(self):

        return util.is_lnd_running(self.network, self.wallet_name)

    def monitor(self):
        js,e = self.run('state')
        while e or ('state' in js 
                and js['state'] not in ['RPC_ACTIVE', 'SERVER_ACTIVE', 'LOCKED','NON_EXISTING']):
            time.sleep(5)            
            js,e = self.run('state')
        return js, e

    def run(self, command, args=''):
        cmd = f'{self.cmd} {command} {args}'
        p = subprocess.run(cmd.split(), capture_output=True, text=True)
        js = {}
        # print(f'### cmd   : {cmd}')
        # print(f'### stdout: {p.stdout}')
        # print(f'### stderr: {p.stderr}')
        if p.stdout:
            js = json.loads(p.stdout)

        return js, p.stderr

    def create(self, password):
        cmd = f'{self.cmd} create'
        print('wexpect.spawn:', cmd)
        p = wexpect.spawn(cmd)
        print(cmd)
        i = p.expect (['password:', wexpect.EOF, wexpect.TIMEOUT], timeout=5)
        print(i)
        if i > 0:
            return p.before.strip()
        print('sending command after expect 1....')
        p.sendline(password)
        i = p.expect (['password:', wexpect.EOF, wexpect.TIMEOUT], timeout=5)
        print(i)
        if i > 0:
            return p.before.strip()
        print('sending command after expect 2....')
        p.sendline(password)
        i = p.expect (['Enter y/x/n', wexpect.EOF, wexpect.TIMEOUT], timeout=5)
        print(i)
        if i > 0:
            return p.before.strip()
        print('sending command after expect 3....')
        p.sendline('n')
        i = p.expect (['passphrase', wexpect.EOF, wexpect.TIMEOUT], timeout=5)
        print(i)
        if i > 0:
            return p.before.strip()
        print('sending command after expect 4....')
        p.sendline('')
        i = p.expect([wexpect.EOF, wexpect.TIMEOUT], timeout=5)
        print(i)
        if i > 0:
            return p.before.strip()
        print('returning ok....')
        return 'OK'      

    def unlock(self, password):
        print('wallet unlocking...')
        cmd = f'{self.cmd} unlock'
        print(cmd)
        p = wexpect.spawn(cmd)
        i = p.expect (['password:', wexpect.EOF, wexpect.TIMEOUT], timeout=5)
        if i == 0:
            p.sendline(password)
            i = p.expect (['password:', wexpect.EOF, wexpect.TIMEOUT], timeout=5)
            if i == 0:
                return 'wrong password :('
            elif i == 1:
                if 'unlocked' in p.before:
                    return 'OK'
                else:
                    return p.before.strip()
            elif i == 2:
                return 'timeout'
        elif i == 1:
            return p.before.strip()
        elif i == 2:
            return 'timeout'

    def connect(self, node_url):
        o,e = self.run('connect', node_url)
        return e

    def channel(self, node_key, local_amount, remote_amount):
        args = f'--node_key={node_key} --local_amt={local_amount}'
        if remote_amount > 0:
            args = f'{args} --push_amt={remote_amount}'
        o,e = self.run('openchannel', args)
        return e

    def close_channel(self, channel_point):
        funding_txid = channel_point.split(':')[0]
        output_index = channel_point.split(':')[1]
        args = f'{args} --funding_txid={funding_txid} --output_index={output_index}'
        o,e = self.run('closechannel', args)
        return e

    def invoice(self, amount):
        return self.run('addinvoice', f'--amt={amount}')

    def pay(self, pay_req):
        cmd = f'{self.cmd} sendpayment --pay_req={pay_req}'
        p = wexpect.spawn(cmd)
        i = p.expect (['yes/no', wexpect.EOF, wexpect.TIMEOUT], timeout=5)
        if i > 0:
            return '', p.before.strip()
        p.sendline('yes')
        i = p.expect ([wexpect.EOF, wexpect.TIMEOUT], timeout=5)
        if i > 0:
            return '', p.before.strip()
        return 'OK', ''

        
