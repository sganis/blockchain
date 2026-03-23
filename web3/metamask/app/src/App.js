// Importing modules
import { useState } from "react";
import { ethers } from "ethers";
import "./App.css";
import "bootstrap/dist/css/bootstrap.min.css";

function App() {
const [address, setAddress] = useState("");
const [balance, setBalance] = useState(0);

const onClick = async () => {
  if (window.ethereum) {
    try{
      const res = await window.ethereum.request({ 
        method: "eth_requestAccounts" 
      })
      const account = res[0];
      setAddress(account);
      await getBalance(account);
    } catch (error) { }
  } else {
    alert("install metamask extension!!");
  }
};

const getBalance = async (address) => {
  try {
    const balance = await window.ethereum.request({
      method: "eth_getBalance",
      params: [address, "latest"]
    })
    setBalance(ethers.utils.formatEther(balance));
  } catch (error) { }
};

return (
  <div className="App mt-3">
  <div className="text-center">
    <button onClick={onClick} 
      className="btn btn-primary">
      Connect to wallet
    </button><br/>
    <strong>Address: </strong> {address}<br/>
    <strong>Balance: </strong> {balance}<br/>
    </div>
  </div>
);
}

export default App;
