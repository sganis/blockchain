import sys
import os
import subprocess
import time
import json
import psutil
from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot, QThread
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import QApplication, QWidget, QMessageBox
from worker import Worker
from monitor import Monitor
from ui_lnw import Ui_Form
import util

DIR = os.path.dirname(os.path.realpath(__file__))
LOGLEVEL = 'warn'
DATADIR = DIR.replace('\\','/')


# FORM_CLASS, BASE_CLASS = uic.loadUiType('lnw.ui')
# class Window(BASE_CLASS, FORM_CLASS):
class Window(QWidget, Ui_Form):
    runBtcdReq = pyqtSignal(str)
    btcMineReq = pyqtSignal(int)
    changeNetworkReq = pyqtSignal(str)
    createReq = pyqtSignal(str, str)
    changeWalletReq = pyqtSignal(str)
    unlockReq = pyqtSignal(str)
    connectReq = pyqtSignal(str)
    channelReq = pyqtSignal(str,int,int)
    closeChannelReq = pyqtSignal(str)
    invoiceReq = pyqtSignal(int)
    payReq = pyqtSignal(str)
    statusReq = pyqtSignal(str, str)
    monitorReq = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super(QWidget, self).__init__(parent)
        self.setupUi(self)
        self.hideAll()
        self.closing = False
        self.lblStatus.setText('')
        self.tabWidget.setVisible(False)
        
        self.thread = QThread()
        self.worker = Worker('san', 'san', DATADIR, LOGLEVEL)
        self.worker.moveToThread(self.thread)
        self.thread.start()
        self.runBtcdReq.connect(self.worker.runBtcd)
        self.worker.progress.connect(self.onProgress)
        
        self.changeNetworkReq.connect(self.worker.changeNetwork)
        self.worker.changeNetworkDone.connect(self.onChangeNetworkDone)
        self.changeWalletReq.connect(self.worker.changeWallet)
        self.worker.changeWalletDone.connect(self.onChangeWalletDone)
        self.createReq.connect(self.worker.create)
        self.worker.createDone.connect(self.onCreateDone)
        self.unlockReq.connect(self.worker.unlock)
        self.worker.unlockDone.connect(self.onUnlockDone)
        self.connectReq.connect(self.worker.connect)
        self.worker.connectDone.connect(self.onConnectDone)
        self.channelReq.connect(self.worker.channel)
        self.worker.channelDone.connect(self.onChannelDone)
        self.closeChannelReq.connect(self.worker.closeChannel)
        self.worker.closeChannelDone.connect(self.onCloseChannelDone)
        self.invoiceReq.connect(self.worker.invoice)
        self.worker.invoiceDone.connect(self.onInvoiceDone)
        self.payReq.connect(self.worker.pay)
        self.worker.payDone.connect(self.onPayDone)

        self.monitor_thread = QThread()
        self.monitor = Monitor('san', 'san', DATADIR, LOGLEVEL)
        self.monitor.moveToThread(self.monitor_thread)
        self.monitor_thread.start()
        self.monitorReq.connect(self.monitor.monitor)
        self.monitor.monitorStatus.connect(self.onMonitorStatus)
        
        self.changeNetwork()
    
    def changeNetwork(self):
        self.hideAll()
        self.network = self.network = str(self.cboNetwork.currentText()).lower()
        self.lblStatus.setText(f'Starting network {self.network}...')
        self.changeNetworkReq.emit(self.network)

    def onChangeNetworkDone(self, network):
        self.grpWallets.setEnabled(True)
        self.lblStatus.setText('Done')
        self.wallets = [w['name'] for w in util.get_wallets(f'{DATADIR}/wallets', self.network) if w]
        print(self.wallets)
        
        if self.wallets:
            self.cboWallets.clear()
            self.cboWallets.addItems(self.wallets)
            self.changeWallet()
        else:
            self.cboWallets.setVisible(False)

    def onProgress(self, message):
        self.lblStatus.setText(message)

    def onMonitorStatus(self, network, wallet, network_status, wallet_status):
        self.lblNetworkStatus.setText(f'blocks: {network_status}')
        self.lblInfo.setText(wallet_status)
        self.lblStatus.setText('Done.')

    def changeWallet(self):
        self.hideAll()
        self.wallet_name = str(self.cboWallets.currentText())
        if self.wallet_name:
            self.lblStatus.setText(f'Starting wallet {self.wallet_name}...')
            self.changeWalletReq.emit(self.wallet_name)
        else:
            self.cboWallets.setVisible(False)
            self.widgetCreate.setVisible(True)

    def onChangeWalletDone(self, wallet_name, message):
        self.grpWallets.setEnabled(True)
        self.lblInfo.setText(message)
        self.lblSpace.setVisible(True)
        self.tabWidget.setVisible(False)
        if 'LOCKED' in message and 'UNLOCKED' not in message:
            self.cboWallets.setVisible(True)
            self.widgetUnlock.setVisible(True)
            self.widgetUnlock.setEnabled(True)
        elif 'NON_EXISTING' in message:
            self.widgetCreate.setVisible(True)
        else:
            self.tabWidget.setVisible(True)
            self.lblSpace.setVisible(False)
        self.lblStatus.setText('Done.')
        print(f'wallet changed: {self.network} {self.wallet_name} {message}')
        self.monitorReq.emit(self.network, self.wallet_name)

    def on_pbStartWallet_released(self):
        self.pbStartWallet.setEnabled(False)
        self.runWallet1Req.emit('START')

    def on_pbStopWallet_released(self):
        self.pbStopWallet.setEnabled(False)
        self.runWallet1Req.emit('STOP')

    def on_pbShowCreate_released(self):
        self.hideAll()
        self.widgetActions.setEnabled(False)
        self.widgetCreate.setVisible(True)
        self.widgetCreate.setEnabled(True)
        
    def on_pbCancelCreate_released(self):
        self.widgetCreate.setVisible(False)
        self.widgetActions.setEnabled(True)
        self.tabWidget.setVisible(True)
        self.lblSpace.setVisible(False)
        self.monitorReq.emit(self.network, self.wallet_name)
        
    def on_pbCreate_released(self):
        wallets = [str(self.cboWallets.itemText(i)) for i in range(self.cboWallets.count())]
        for w in wallets:
            if w == str(self.widgetCreate.txtNameCreate.text()):
                self.lblStatus.setText('A wallet with the same name already exists.')
                return
        self.lblStatus.setText('Creating wallet...')
        self.widgetCreate.setEnabled(False)
        self.createReq.emit(
            str(self.widgetCreate.txtNameCreate.text()),
            str(self.widgetCreate.txtPasswordCreate.text()))

    def onCreateDone(self, wallet_name, output):
        print(output)
        if 'OK' in output:
            self.wallet_name = wallet_name
            self.widgetActions.setEnabled(True)
            self.tabWidget.setVisible(True)
            self.lblSpace.setVisible(False)
            self.cboWallets.blockSignals(True)
            self.cboWallets.addItem(wallet_name)
            self.cboWallets.setCurrentText(wallet_name)
            self.cboWallets.blockSignals(False)
            self.cboWallets.setVisible(True)
            self.cboWallets.setEnabled(True)
            self.widgetCreate.setVisible(False)
            self.monitorReq.emit(self.network, self.wallet_name)
        else:
            self.widgetCreate.setEnabled(True)
            self.lblStatus.setText(output)
    
    def on_txtNameCreate_returnPressed(self):
    
        self.on_pbCreate_released()

    def on_pbShowConnect_released(self):
        self.hideAll()
        self.widgetActions.setEnabled(False)
        self.widgetConnect.setVisible(True)
        self.widgetConnect.setEnabled(True)
        
    def on_pbCancelConnect_released(self):
        self.widgetConnect.setVisible(False)
        self.widgetActions.setEnabled(True)
        self.tabWidget.setVisible(True)
        self.lblSpace.setVisible(False)
        self.monitorReq.emit(self.network, self.wallet_name)
        
    def on_pbConnect_released(self):
        self.lblStatus.setText('Connecting to peer...')
        self.widgetConnect.setEnabled(False)
        self.connectReq.emit(str(self.widgetConnect.txtNodeUrl.text()))

    def onConnectDone(self, error):
        if not error:
            self.widgetConnect.setVisible(False)
            self.widgetActions.setEnabled(True)
            self.tabWidget.setVisible(True)
            self.lblSpace.setVisible(False)
            self.lblStatus.setText('Done')
            self.monitorReq.emit(self.network, self.wallet_name)
        else:
            self.widgetConnect.setEnabled(True)
            self.lblStatus.setText(error)

    def on_txtNameConnect_returnPressed(self):
    
        self.on_pbConnect_released()

    def on_pbShowChannel_released(self):
        self.hideAll()
        self.widgetChannel.setVisible(True)
        self.widgetChannel.setEnabled(True)
        self.widgetActions.setEnabled(False)
        
    def on_pbCancelChannel_released(self):
        self.widgetChannel.setVisible(False)
        self.widgetActions.setEnabled(True)
        self.tabWidget.setVisible(True)
        self.lblSpace.setVisible(False)
        self.monitorReq.emit(self.network, self.wallet_name)
        
    def on_pbChannel_released(self):
        nodekey = str(self.widgetChannel.txtNodeKey.text())
        local = str(self.widgetChannel.txtLocalAmount.text())
        remote = str(self.widgetChannel.txtRemoteAmount.text())
        if not nodekey:
            self.lblStatus.setText('Node key is required')
            return
        if (str(util.to_int(local)) != local and util.to_int(local) < 1):            
            self.lblStatus.setText('Integer amount is required')
            return
        local = util.to_int(local)
        if (remote and str(util.to_int(remote)) != remote and util.to_int(remote) < 0):            
            self.lblStatus.setText('Integer amount is required')
            return
        remote = util.to_int(remote)
        
        self.lblStatus.setText('Opening channel...')
        self.widgetChannel.setEnabled(False)
        self.channelReq.emit(nodekey, local, remote)

    def onChannelDone(self, error):
        if not error:
            self.widgetChannel.setVisible(False)
            self.widgetActions.setEnabled(True)
            self.tabWidget.setVisible(True)
            self.lblSpace.setVisible(False)
            self.lblStatus.setText('Done')
            self.monitorReq.emit(self.network, self.wallet_name)
        else:
            self.widgetChannel.setEnabled(True)
            self.lblStatus.setText(error)

    def on_pbCloseChannel_released(self):
        dlg = QMessageBox(self)
        dlg.setWindowTitle("")
        dlg.setText("Close channel?")
        dlg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        dlg.setIcon(QMessageBox.Icon.Question)
        r = dlg.exec()
        if r == QMessageBox.StandardButton.Yes:
            self.lblStatus.setText('Closing channel...')
            self.closeChannelReq.emit(channel_point)

    def onCloseChannelDone(self, error):
        if not error:
            self.widgetActions.setEnabled(True)
            self.tabWidget.setVisible(True)
            self.lblSpace.setVisible(False)
            self.lblStatus.setText('Done')
            self.monitorReq.emit(self.network, self.wallet_name)
        else:
            self.lblStatus.setText(error)

    def on_pbShowInvoice_released(self):
        self.hideAll()
        self.widgetInvoice.setVisible(True)
        self.widgetInvoice.setEnabled(True)
        self.widgetActions.setEnabled(False)
        
    def on_pbCancelInvoice_released(self):
        self.widgetInvoice.setVisible(False)
        self.widgetActions.setEnabled(True)
        self.tabWidget.setVisible(True)
        self.lblSpace.setVisible(False)
        self.monitorReq.emit(self.network, self.wallet_name)
        
    def on_pbInvoice_released(self):
        amount = str(self.widgetInvoice.txtInvoiceAmount.text())
        if (str(util.to_int(amount)) != amount and util.to_int(amount) < 1):            
            self.lblStatus.setText('Integer amount is required')
            return
        amount = util.to_int(amount)
        
        self.lblStatus.setText('Creating invoice...')
        self.widgetInvoice.setEnabled(False)
        self.invoiceReq.emit(amount)

    def onInvoiceDone(self, output, error):
        if not error:
            print(output)
            self.widgetInvoice.setVisible(False)
            self.widgetActions.setEnabled(True)
            self.tabWidget.setVisible(True)
            self.lblSpace.setVisible(False)
            self.tabWidget.setCurrentIndex(3)
            self.lblPayments.setText(output)
            self.lblStatus.setText('Done')
            
            import qrcode
            from io import BytesIO
            buf = BytesIO()
            img = qrcode.make(output)
            img.save(buf, "PNG")
            qt_pixmap = QPixmap()
            qt_pixmap.loadFromData(buf.getvalue(), "PNG")
            self.lblQr.resize(200,200)
            self.lblQr.setPixmap(qt_pixmap)
            self.widgetQr.setVisible(True)

            self.tabWidget.setVisible(False)
            self.lblSpace.setVisible(True)

            self.monitorReq.emit(self.network, self.wallet_name)


        else:
            self.widgetInvoice.setEnabled(True)
            self.lblStatus.setText(error)

    def on_pbShowPay_released(self):
        self.hideAll()
        self.widgetPay.setVisible(True)
        self.widgetPay.setEnabled(True)
        self.widgetActions.setEnabled(False)
        
    def on_pbCancelPay_released(self):
        self.widgetPay.setVisible(False)
        self.widgetActions.setEnabled(True)
        self.tabWidget.setVisible(True)
        self.lblSpace.setVisible(False)
        self.monitorReq.emit(self.network, self.wallet_name)
        
    def on_pbPay_released(self):
        pay_req = str(self.widgetPay.txtPayRequest.text())
        if not pay_req:
            self.lblStatus.setText('Payment request is required')
            return
        self.lblStatus.setText('Sending payment...')
        self.widgetPay.setEnabled(False)
        self.payReq.emit(pay_req)

    def onPayDone(self, output, error):

        if not error:
            self.widgetPay.setVisible(False)
            self.widgetActions.setEnabled(True)
            self.tabWidget.setVisible(True)
            self.lblSpace.setVisible(False)
            self.lblStatus.setText('Done')
            self.monitorReq.emit(self.network, self.wallet_name)
        else:
            self.widgetPay.setEnabled(True)
            self.lblStatus.setText(error)

    @pyqtSlot(str)
    def on_cboWallets_currentTextChanged(self, name):
        self.changeWallet()

    def on_cboNetwork_currentTextChanged(self, network):
        self.network = network.lower()
        self.grpWallets.setEnabled(False)
        self.lblStatus.setText(f'Starting {self.network}...')
        self.changeNetworkReq.emit(network.lower())
    
    def on_pbUnlock_released(self):
        self.lblStatus.setText('Unlocking...')
        self.widgetUnlock.setEnabled(False)
        self.unlockReq.emit(str(self.widgetUnlock.txtPasswordUnlock.text()))

    def onUnlockDone(self, output):
        print('unlock done', output)
        if 'OK' in output:
            self.widgetUnlock.setVisible(False)
            self.tabWidget.setVisible(True)
            self.lblSpace.setVisible(False)
            self.lblStatus.setText('Wallet unlocked, getting status...')  
            self.monitorReq.emit(self.network, self.wallet_name)
                    
        else:
            self.widgetUnlock.setEnabled(True)
            self.lblStatus.setText(output)
    
    def hideAll(self):
        self.widgetCreate.setVisible(False)
        self.widgetUnlock.setVisible(False)
        self.widgetConnect.setVisible(False)
        self.widgetChannel.setVisible(False)
        self.widgetInvoice.setVisible(False)
        self.widgetQr.setVisible(False)
        self.widgetPay.setVisible(False)
        self.tabWidget.setVisible(False)
        # self.cboWallets.setVisible(False)
        # self.pbShowCreate.setVisible(False)
        self.lblSpace.setVisible(True)

    def stopServices(self):
        dlg = QMessageBox(self)
        dlg.setWindowTitle("Btcd and Lnd")
        dlg.setText("Stop services?")
        dlg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No| QMessageBox.StandardButton.Cancel)
        dlg.setIcon(QMessageBox.Icon.Question)
        r = dlg.exec()
        if r == QMessageBox.StandardButton.Yes:
            return 1
        elif r == QMessageBox.StandardButton.No:
            return 0
        else:
            return -1
            
    def closeEvent(self, e):
        r = self.stopServices()
        if r == -1:
            e.ignore()
            return
        stop = r == 1
        if stop:
            self.worker.stopBtcd()
            self.worker.stopWallet()
        self.closing = True
        self.thread.quit()
        self.thread.wait()
        self.monitor.stop()
        self.monitor_thread.quit()
        self.monitor_thread.wait()
        if stop:
            if util.is_process_running('btcd.exe'):
                os.system('taskkill /im btcd.exe /f')
            if util.is_process_running('lnd.exe'):
                os.system('taskkill /im lnd.exe /f')


if __name__ == '__main__':
  
    app = QApplication(sys.argv)
    window = Window()
    window.show()
    sys.exit(app.exec())