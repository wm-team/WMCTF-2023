pragma solidity ^0.5.0;

contract Challenge {
    bool public solved = false;
    uint256 private secretNumber;

    constructor() public {
        secretNumber = block.timestamp % 10 + 1;
    }

    function guessNumber(uint256 _num) public {
        uint256 num = _num;

        assembly {
            let m := mload(0x40)
            let a := and(sload(secretNumber_slot), 1)
            let b := and(num, 1)
            let result := eq(a, b)
            mstore(m, result)
            sstore(solved_slot, result)
        }
    }

    function isSolved() public view returns (bool) {
        return solved;
    }
}
