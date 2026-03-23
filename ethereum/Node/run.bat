:: start ethereum node in port 8545
geth --rinkeby ^
	--http ^
	--syncmode=light ^
	--http.api="eth,net,web3,personal,txpool,admin,debug" ^
	--rpccorsdomain="chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn"
