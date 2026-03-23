:: @echo off
setlocal
set DIR=%~dp0
set DIR=%DIR:~0,-1%
set PWD=%cd%
cd %DIR%

pyuic6 ui\lnw.ui 	> ui_lnw.py
pyuic6 ui\create.ui > ui_create.py
pyuic6 ui\unlock.ui > ui_unlock.py
pyuic6 ui\connect.ui > ui_connect.py
pyuic6 ui\channel.ui > ui_channel.py
pyuic6 ui\invoice.ui > ui_invoice.py
pyuic6 ui\pay.ui > ui_pay.py

cd %PWD%
