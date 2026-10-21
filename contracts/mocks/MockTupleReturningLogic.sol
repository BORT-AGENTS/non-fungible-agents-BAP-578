// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice ABI-independent stand-in for stock logic modules returning (bool, bytes).
/// @dev Deliberately does not inherit the forwarder's interface: an incorrect
///      interface must not silently change the fixture's ABI along with it.
contract MockTupleReturningLogic {
    address public immutable FORWARDER;
    uint256 public lastTokenId;
    string public lastAction;
    bytes public lastData;
    uint256 public callCount;

    constructor(address forwarder_) {
        FORWARDER = forwarder_;
    }

    function handleAction(
        uint256 tokenId,
        string calldata action,
        bytes calldata data
    ) external returns (bool success, bytes memory result) {
        require(msg.sender == FORWARDER, "logic: unauthorized caller");

        lastTokenId = tokenId;
        lastAction = action;
        lastData = data;
        callCount++;
        require(keccak256(bytes(action)) != keccak256("revert"), "logic: action reverted");

        return (keccak256(bytes(action)) != keccak256("reject"), data);
    }
}
