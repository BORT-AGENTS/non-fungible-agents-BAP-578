// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IAgentStateResolver } from "../IAgentStateResolver.sol";
import { IBAP578 as ICLAWNFA } from "../../claw/CLAWNFA.sol";

interface ICLAWNFACollection is ICLAWNFA {
    function ownerOf(uint256 tokenId) external view returns (address);
    function paused() external view returns (bool);
}

/// @notice Adapter for contracts/claw/CLAWNFA.sol (getState, not agentStates).
/// @dev This profile has no authoritative ownership nonce.
contract CLAWNFAStateResolver is IAgentStateResolver {
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
        ICLAWNFACollection nft = ICLAWNFACollection(collection);
        state.owner = nft.ownerOf(tokenId);
        ICLAWNFA.State memory raw = nft.getState(tokenId);
        state.logicAddress = raw.logicAddress;
        state.active = raw.status == ICLAWNFA.Status.Active && !nft.paused();
    }
}
