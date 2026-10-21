// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IAgentStateResolver } from "../IAgentStateResolver.sol";

interface IAuthoritativeAgentRevisions {
    function ownershipNonce(uint256 tokenId) external view returns (uint256);
    function executionRevision(uint256 tokenId) external view returns (uint256);
}

/// @notice Adds authoritative ownership and execution counters supplied by the actual collection.
/// @dev This wrapper does not manufacture either guarantee. Use ONLY where the
///      collection advances non-resetting counters atomically on every ownership
///      change (including burn/remint) and every execution module/version change
///      (including upgrades behind an unchanged proxy). Every relevant upgrade
///      path must participate. The source remains trusted for owner, module and lifecycle.
contract AuthoritativeStateResolver is IAgentStateResolver {
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

    function supportsExecutionRevision() external pure returns (bool) {
        return true;
    }

    function getAgentState(uint256 tokenId) external view returns (AgentState memory state) {
        state = SOURCE.getAgentState(tokenId);
        state.ownershipNonce = IAuthoritativeAgentRevisions(collection).ownershipNonce(tokenId);
        state.executionRevision = IAuthoritativeAgentRevisions(collection).executionRevision(
            tokenId
        );
    }
}
