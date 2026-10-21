// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IAgentStateResolver } from "../IAgentStateResolver.sol";

interface IAgentOwnershipNonce {
    function ownershipNonce(uint256 tokenId) external view returns (uint256);
}

/// @notice Adds the nonce profile to a collection-specific state resolver.
/// @dev Use ONLY when the actual collection increments ownershipNonce on EVERY
///      ownership change. This wrapper does not create or infer transfer history.
contract NonceTrackedStateResolver is IAgentStateResolver {
    IAgentStateResolver public immutable SOURCE;
    address public immutable override collection;

    constructor(address source_) {
        require(source_.code.length > 0, "Resolver: source has no code");
        SOURCE = IAgentStateResolver(source_);
        address nft = IAgentStateResolver(source_).collection();
        require(nft.code.length > 0, "Resolver: collection has no code");
        collection = nft;
    }

    function supportsOwnershipNonce() external pure returns (bool) {
        return true;
    }

    function supportsExecutionRevision() external view returns (bool) {
        return SOURCE.supportsExecutionRevision();
    }

    function getAgentState(uint256 tokenId) external view returns (AgentState memory state) {
        state = SOURCE.getAgentState(tokenId);
        state.ownershipNonce = IAgentOwnershipNonce(collection).ownershipNonce(tokenId);
    }
}
