const { ethers } = require("ethers");
require("dotenv").config({ path: `${__dirname}/../.env` });
INFURA_ID = process.env.INFURA_ID;
const MY_ADDRESS_1 = process.env.MY_ADDRESS_1;
const MY_ADDRESS_2 = process.env.MY_ADDRESS_2;

// const provider = new ethers.providers.JsonRpcProvider(
//   `https://goerli.infura.io/v3/${INFURA_ID}`
// );

// metamask
// const provider = new ethers.providers.Web3Provider(window.ethereum, "any");

const main = async () => {
  const url = "http://localhost:7545";

  // Or if you are running the UI version, use this instead:
  // const url = "http://localhost:7545"

  const provider = new ethers.providers.JsonRpcProvider(url);

  // Getting the accounts
  const signer0 = provider.getSigner(0);
  const signer1 = provider.getSigner(1);
  const address0 = await signer0.getAddress();
  const address1 = await signer1.getAddress();

  console.log("Account0:", address0);
  console.log("Account1:", address1);

  const senderBalanceBefore = await provider.getBalance(address0);
  const recieverBalanceBefore = await provider.getBalance(address1);

  console.log(
    `\nSender balance before: ${ethers.utils.formatEther(senderBalanceBefore)}`
  );
  console.log(
    `reciever balance before: ${ethers.utils.formatEther(recieverBalanceBefore)}\n`
  );

  const tx = await signer0.sendTransaction({
    to: address1,
    value: ethers.utils.parseEther("1.0"),
  });

  console.log(tx);

  const senderBalanceAfter = await provider.getBalance(address0);
  const recieverBalanceAfter = await provider.getBalance(address1);

  console.log(
    `\nSender balance after: ${ethers.utils.formatEther(senderBalanceAfter)}`
  );
  console.log(
    `reciever balance after: ${ethers.utils.formatEther(recieverBalanceAfter)}\n`
  );
};

main();
