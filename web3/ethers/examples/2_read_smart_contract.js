const { ethers } = require("ethers");
require("dotenv").config({ path: `${__dirname}/../.env` });
INFURA_ID = process.env.INFURA_ID;
const MY_ADDRESS_1 = process.env.MY_ADDRESS_1;

const provider = new ethers.providers.JsonRpcProvider(
  `https://goerli.infura.io/v3/${INFURA_ID}`
);

const ERC20_ABI = [
  "function name() view returns (string)",
  "function symbol() view returns (string)",
  "function totalSupply() view returns (uint256)",
  "function balanceOf(address) view returns (uint)",
];

const link_address = "0x326c977e6efc84e512bb9c30f76e30c160ed06fb"; // LINK Contract
const contract = new ethers.Contract(link_address, ERC20_ABI, provider);

const main = async () => {
  const name = await contract.name();
  const symbol = await contract.symbol();
  const totalSupply = await contract.totalSupply();

  console.log(`\nReading from ${link_address}\n`);
  console.log(`Name: ${name}`);
  console.log(`Symbol: ${symbol}`);
  console.log(`Total Supply: ${totalSupply}\n`);

  const balance = await contract.balanceOf(MY_ADDRESS_1);

  console.log(`Balance Returned: ${balance}`);
  console.log(`Balance Formatted: ${ethers.utils.formatEther(balance)}\n`);
};

main();
