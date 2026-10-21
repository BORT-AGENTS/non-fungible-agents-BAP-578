// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal mock of the BAP578 surface read by the execution resolver.
///         Used only by VaultPermissionManager.test.js. Not for production.
contract MockBAP578ForVPM {
    bool public paused;
    mapping(uint256 => address) public ownerOf;

    struct AgentState {
        uint256 balance;
        bool active;
        address logicAddress;
        uint256 createdAt;
    }

    mapping(uint256 => AgentState) public agentStates;

    function mint(uint256 tokenId, address to, address logicAddress) external virtual {
        ownerOf[tokenId] = to;
        agentStates[tokenId] = AgentState({
            balance: 0,
            active: true,
            logicAddress: logicAddress,
            createdAt: block.timestamp
        });
    }

    function setLogic(uint256 tokenId, address logicAddress) external {
        agentStates[tokenId].logicAddress = logicAddress;
    }

    function setPaused(bool pauseState) external {
        paused = pauseState;
    }

    function setActive(uint256 tokenId, bool active) external {
        agentStates[tokenId].active = active;
    }

    function transfer(uint256 tokenId, address to) external virtual {
        ownerOf[tokenId] = to;
    }
}
