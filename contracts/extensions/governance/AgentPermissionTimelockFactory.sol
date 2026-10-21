// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { AgentPermissionTimelock } from "./AgentPermissionTimelock.sol";

/// @notice Authenticates concrete timelocks through their creation path.
/// @dev No administrator, proxy, arbitrary registration or implementation choice.
///      The manager pins a factory created by its implementation constructor.
///      Any account may create a timelock; initialization still chooses its council.
contract AgentPermissionTimelockFactory {
    mapping(address => bool) public isGovernance;

    event TimelockCreated(
        address indexed governance,
        address indexed proposerCouncil,
        uint256 delay
    );

    function createTimelock(uint256 delay, address council) external returns (address governance) {
        governance = address(new AgentPermissionTimelock(delay, council));
        isGovernance[governance] = true;
        emit TimelockCreated(governance, council, delay);
    }
}
