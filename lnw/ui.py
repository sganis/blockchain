#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
from PyQt6.QtWidgets import QWidget
from ui_create import Ui_Create
from ui_unlock import Ui_Unlock
from ui_connect import Ui_Connect
from ui_channel import Ui_Channel
from ui_invoice import Ui_Invoice
from ui_pay import Ui_Pay


class Create(QWidget, Ui_Create):
    def __init__(self, parent=None):
        QWidget.__init__(self, parent)
        self.setupUi(self)

class Unlock(QWidget, Ui_Unlock):
    def __init__(self, parent=None):
        QWidget.__init__(self, parent)
        self.setupUi(self)

class Connect(QWidget, Ui_Connect):
    def __init__(self, parent=None):
        QWidget.__init__(self, parent)
        self.setupUi(self)
                
class Channel(QWidget, Ui_Channel):
    def __init__(self, parent=None):
        QWidget.__init__(self, parent)
        self.setupUi(self)

class Invoice(QWidget, Ui_Invoice):
    def __init__(self, parent=None):
        QWidget.__init__(self, parent)
        self.setupUi(self)

class Pay(QWidget, Ui_Pay):
    def __init__(self, parent=None):
        QWidget.__init__(self, parent)
        self.setupUi(self)
