// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IAgentStateResolver } from "../IAgentStateResolver.sol";

interface ILegacyBAP578Collection {
    function ownerOf(uint256 tokenId) external view returns (address);
    function paused() external view returns (bool);
    function agentStates(
        uint256 tokenId
    ) external view returns (uint256 balance, bool active, address logicAddress, uint256 createdAt);
}

/// @notice Adapter for this repository's legacy contracts/BAP578.sol profile.
/// @dev Owner observation cannot detect an unobserved A-to-B-to-A transfer.
contract LegacyBAP578StateResolver is IAgentStateResolver {
    address public immutable override collection;

    constructor(address collection_) {
        require(collection_.code.length > 0, "Resolver: collection has no code");
        collection = collection_;
    }

    function supportsOwnershipNonce() external pure returns (bool) {
        return false;
    }

    function supportsExecutionRevision() external pure returns (bool) {
        return false;
    }

    function getAgentState(uint256 tokenId) external view returns (AgentState memory state) {
        ILegacyBAP578Collection nft = ILegacyBAP578Collection(collection);
        state.owner = nft.ownerOf(tokenId);
        (, bool active, address logic, ) = nft.agentStates(tokenId);
        state.logicAddress = logic;
        state.active = active && !nft.paused();
    }
}
