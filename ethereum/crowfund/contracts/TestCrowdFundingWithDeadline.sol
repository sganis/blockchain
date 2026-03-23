// SPDX-License-Identifier: MIT
pragma solidity >=0.5.0;
import "./CrowdFundingWithDeadline.sol";

contract TestCrowdFundingWithDeadline is CrowdFundingWithDeadline {
    uint256 time;

    constructor(
        string memory contractName,
        uint256 targetAmountEth,
        uint256 durationInMin,
        address payable beneficiaryAddress
    )
        CrowdFundingWithDeadline(
            contractName,
            targetAmountEth,
            durationInMin,
            beneficiaryAddress
        )
    {}

    function currentTime() internal view override returns (uint256) {
        return time;
    }

    function setCurrentTime(uint256 newTime) public {
        time = newTime;
    }
}
