from brownie import network, accounts, config

LOCAL_BLOCKCHAIN_ENVIRONMENTS = ["hardhat", 
    "development", "mainnet-fork","Ganache-UI"]


def get_account():
    print(network.show_active())
    if network.show_active() in LOCAL_BLOCKCHAIN_ENVIRONMENTS:
        return accounts[0]
    if network.show_active() in config["networks"]:
        account = accounts.add(config["wallets"]["from_key"])
        return account
    return None

if __name__ == '__main__':
    a = get_account()
    print(a)