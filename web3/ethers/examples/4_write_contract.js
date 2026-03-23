const { ethers } = require("ethers");
require("dotenv").config({ path: `${__dirname}/../.env` });
INFURA_ID = process.env.INFURA_ID;

const main = async () => {
  const url = "http://localhost:7545";
  const provider = new ethers.providers.JsonRpcProvider(url);

  // Getting the accounts
  const signer0 = provider.getSigner(0);
  const signer1 = provider.getSigner(1);
  const address0 = await signer0.getAddress();
  const address1 = await signer1.getAddress();

  console.log("Account0:", address0);
  console.log("Account1:", address1);

  const ERC20_ABI = [
    "function balanceOf(address) view returns (uint)",
    "function transfer(address to, uint amount) returns (bool)",
  ];

  const address = "0xcFB52c81e168e88D2d4cb1A27E3f76BF8538fc73";
  const contract = new ethers.Contract(address, ERC20_ABI, provider);

  const balance1 = await contract.balanceOf(address1);
  const balance0 = await contract.balanceOf(address0);

  console.log(`\nReading from ${address}`);
  console.log(`Balance of sender: ${balance1}`);
  console.log(`Balance of reciever: ${balance0}`);

  const contractWithSigner = contract.connect(signer1);
  console.log(`Contract with signer0 created`);

  const tx = await contractWithSigner.transfer(address0, balance1);

  console.log(`Transfered ok\n`);
  console.log(tx);

  const balanceOfSender = await contract.balanceOf(address1);
  const balanceOfReciever = await contract.balanceOf(address0);

  console.log(`\nBalance of sender: ${balanceOfSender}`);
  console.log(`Balance of reciever: ${balanceOfReciever}\n`);
};

main();
