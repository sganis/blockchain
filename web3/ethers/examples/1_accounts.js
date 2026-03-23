const { ethers } = require("ethers");
require("dotenv").config({ path: `${__dirname}/../.env` });
INFURA_ID = process.env.INFURA_ID;
MY_ADDRESS_1 = process.env.MY_ADDRESS_1;

const provider = new ethers.providers.JsonRpcProvider(
  `https://goerli.infura.io/v3/${INFURA_ID}`
);

const main = async () => {
  const balance = await provider.getBalance(MY_ADDRESS_1);
  console.log(
    `\nETH Balance of ${MY_ADDRESS_1} --> ${ethers.utils.formatEther(
      balance
    )} ETH\n`
  );
};

main();
