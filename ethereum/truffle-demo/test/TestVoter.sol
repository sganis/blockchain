// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.0 <0.9.0;

import "truffle/Assert.sol";
import "../contracts/Voter.sol";

contract TestVoter {
    function testVoteForAnOptionUsingNumericIndex() public {
        Voter voter = new Voter();
        voter.addOption("one");
        voter.addOption("two");
        voter.startVoting();

        voter.vote(0);
        uint256[] memory votes = voter.getVotes();
        uint256[] memory expected = new uint256[](2);
        expected[0] = 1;
        expected[1] = 0;
        Assert.equal(votes, expected, "First option should be voted for");
    }
}
