// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Collection-specific, read-only state used by the permission manager.
/// @dev A resolver is trusted code pinned when the manager is initialized.
interface IAgentStateResolver {
    struct AgentState {
        address owner;
        address logicAddress;
        bool active;
        uint256 ownershipNonce;
        uint256 executionRevision;
    }

    function collection() external view returns (address);

    /// @notice True only if the collection provides an authoritative counter
    ///         incremented on every ownership change, including atomic round trips.
    function supportsOwnershipNonce() external view returns (bool);

    /// @notice True only if the actual execution configuration has a monotonic
    ///         revision advanced atomically on every module/version change,
    ///         including proxy upgrades. Address/codehash alone is insufficient.
    function supportsExecutionRevision() external view returns (bool);

    /// @dev Unsupported counters return zero. Unknown tokens MUST revert
    ///      or return a zero owner, which the manager rejects.
    function getAgentState(uint256 tokenId) external view returns (AgentState memory);
}
