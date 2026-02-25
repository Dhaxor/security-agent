// SPDX-License-Identifier: MIT
pragma solidity 0.7.0;

contract TestSolidity {
    function test() public pure returns (string memory) {
        return "Hello, World!";
    }

    function test2() public pure returns (uint256) {
        return type(uint256).max + type(uint256).max;
    }

    function kill() public{
        selfdestruct(msg.sender);
    }    
}