// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

contract Voter {
    struct OptionPos {
        uint256 pos;
        bool exists;
    }

    uint256[] public votes;
    mapping(address => bool) hasVoted;
    mapping(string => OptionPos) posOfOption;
    string[] public options;
    bool votingStarted;

    function addOption(string memory option) public {
        require(!votingStarted, "Voting has already started");
        options.push(option);
    }

    function startVoting() public {
        require(!votingStarted, "Voting has already started");
        //votes.length = options.length;

        for (uint256 i = 0; i < options.length; i++) {
            OptionPos memory option = OptionPos(i, true);
            posOfOption[options[i]] = option;
        }
        votingStarted = true;
    }

    function vote(uint256 option) public {
        require(0 <= option && option < options.length, "Invalid option");
        require(!hasVoted[msg.sender], "Account has already voted");

        hasVoted[msg.sender] = true;
        votes[option] = votes[option] + 1;
    }

    function vote(string memory option) public {
        require(!hasVoted[msg.sender], "Account has already voted");
        OptionPos memory optionPos = posOfOption[option];
        require(optionPos.exists, "Option does not exist");

        hasVoted[msg.sender] = true;
        votes[optionPos.pos] = votes[optionPos.pos] + 1;
    }

    function getVotes() public view returns (uint256[] memory) {
        return votes;
    }
}
