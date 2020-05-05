pragma solidity ^0.4.11;

contract Wallet {

    mapping(address => uint) accounts;

    /* this runs when the contract is executed */
    function deposit() public payable {
       accounts[msg.sender] += msg.value;
    }

    function withdraw(address to, uint amount) public {
        require(accounts[msg.sender] >= amount);
        accounts[msg.sender] -= amount;
        to.transfer(amount);
    }

    /* used to read the value of count */
    function getBalance() constant returns (uint) {
       return accounts[msg.sender];
    }

}