// SPDX-License-Identifier: MIT
pragma solidity >=0.5.0;

library Utils {
    function etherToWei(uint256 sumInEth) public pure returns (uint256) {
        return sumInEth * 1 ether;
    }

    function minutesToSeconds(uint256 timeInMin) public pure returns (uint256) {
        return timeInMin * 1 minutes;
    }
}
