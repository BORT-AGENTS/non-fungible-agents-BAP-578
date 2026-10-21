// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IAgentStateResolver } from "./IAgentStateResolver.sol";
import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @title IAgentExecutionPermissionsV1: per-agent delegation, draft reference profile
/// @notice A vault is a named ACL, not asset custody or an action allowlist.
///         WRITE authorizes the bound logic's entire handleAction surface unless
///         that logic enforces an additional authenticated policy.
/// @dev See EXTENSION-README.md at the repository root for normative rules,
///      ownership tracking profiles, deployment trust, and policy composition.
interface IAgentExecutionPermissionsV1 is IERC165 {
    enum ProtectionProfile {
        STRICT,
        LEGACY_COMPATIBILITY
    }
    enum PermissionLevel {
        NONE,
        READ,
        WRITE,
        ADMIN
    }

    struct Grant {
        PermissionLevel level;
        uint256 expiry;
        uint256 epoch;
        address parentAdmin;
        uint256 parentGeneration;
        uint256 generation;
        bool exists;
    }

    struct ForwardContext {
        uint256 tokenId;
        bytes32 vaultIdHash;
        address accessor;
        address logicAddress;
        uint256 ownershipNonce;
        uint256 executionRevision;
    }

    event VaultCreated(
        uint256 indexed tokenId,
        bytes32 indexed vaultIdHash,
        string vaultId,
        address creator,
        string description
    );
    event PermissionGranted(
        uint256 indexed tokenId,
        bytes32 indexed vaultIdHash,
        address indexed grantee,
        PermissionLevel level,
        uint256 expiry,
        string description,
        address grantor,
        uint256 generation,
        address parentAdmin,
        uint256 parentGeneration
    );
    event PermissionRevoked(
        uint256 indexed tokenId,
        bytes32 indexed vaultIdHash,
        address indexed grantee
    );
    /// @notice Dispatch only. Receipt success and this event do not mean the
    ///         action returned true; consume ActionResult for the action outcome.
    event ActionForwarded(
        uint256 indexed tokenId,
        bytes32 indexed vaultIdHash,
        address indexed accessor,
        string action
    );
    event ActionResult(
        uint256 indexed tokenId,
        bytes32 indexed vaultIdHash,
        address indexed accessor,
        address logicAddress,
        bool success,
        bytes32 resultHash
    );
    /// @dev Owners can be equal for an execution change or ownership round trip.
    event AgentEpochAdvanced(
        uint256 indexed tokenId,
        address indexed previousOwner,
        address indexed newOwner,
        uint256 newEpoch
    );
    event PermissionsReset(uint256 indexed tokenId, address indexed owner, uint256 newEpoch);
    event ManagerPauseChanged(bool paused, address indexed caller);
    event PauseGuardianChanged(address indexed previousGuardian, address indexed newGuardian);

    /// @notice Public deployment profile. Address pinning does not remove the
    ///         trust in an upgradeable resolver, collection, or VPM implementation.
    function collection() external view returns (address);
    function resolver() external view returns (IAgentStateResolver);
    function ownershipNonceSupported() external view returns (bool);
    function executionRevisionSupported() external view returns (bool);
    function protectionProfile() external view returns (ProtectionProfile);
    function paused() external view returns (bool);
    function extensionId() external pure returns (bytes32);
    function extensionVersion() external pure returns (uint256);
    function governance() external view returns (address);
    function governanceMinDelay() external view returns (uint256);
    function governanceProfile() external pure returns (bytes32);
    function pauseGuardian() external view returns (address);

    /// @notice NFT-owner-only creation of a nonempty, case-sensitive namespace.
    /// @dev Descriptions are public event data, not stored secrets.
    function createVault(
        uint256 tokenId,
        string calldata vaultId,
        string calldata description
    ) external;

    /// @notice Create or replace one grant. The owner has implicit ADMIN and
    ///         cannot receive an explicit grant. Nobody can grant to itself.
    /// @dev Only the owner creates ADMIN. An ADMIN can manage its own READ/WRITE
    ///      children; children depend on that ADMIN's current grant generation.
    /// @param expiry Inclusive last-valid timestamp, or 0 for no expiry. A finite
    ///        ADMIN cannot create a permanent child or outlive its own expiry.
    function grantPermission(
        uint256 tokenId,
        string calldata vaultId,
        address grantee,
        PermissionLevel level,
        uint256 expiry,
        string calldata description
    ) external;

    /// @notice Owner revokes any grant; ADMIN revokes its own children or itself.
    /// @dev Revoking or replacing ADMIN invalidates its children without deleting
    ///      raw records. A later ADMIN renewal does not resurrect old children.
    function revokePermission(uint256 tokenId, string calldata vaultId, address grantee) external;

    /// @notice Dispatch to the current active logic after owner/WRITE checks.
    /// @dev Returns false results unchanged; their downstream state changes may
    ///      persist. Reverts and ABI decoding failures roll the entire call back.
    ///      Ordinary Solidity decoding does not validate strict-canonical encoding.
    ///      Result copying and revert propagation remain bounded by transaction gas.
    function forwardHandleAction(
        uint256 tokenId,
        string calldata vaultId,
        string calldata action,
        bytes calldata data
    ) external returns (bool success, bytes memory result);

    /// @notice Commit ownership and execution observations. Reverts never commit.
    /// @dev Owner-observation mode cannot detect an unobserved round trip.
    ///      Nonce mode requires the collection's authoritative transfer counter.
    function syncAgentState(uint256 tokenId) external;

    /// @notice Owner-only invalidation of all delegated grants; namespaces remain.
    function resetPermissions(uint256 tokenId) external;

    /// @notice Emergency guardian or delayed governor can pause immediately.
    /// @dev Revocation, reset, and ownership synchronization remain available.
    function pause() external;

    /// @notice Only delayed governance can unpause or replace the guardian.
    function unpause() external;
    function setPauseGuardian(address guardian_) external;

    /// @notice Effective ACL permission, including parent validity and implicit
    ///         owner ADMIN. Does not test lifecycle, logic code, or manager pause.
    function checkPermission(
        uint256 tokenId,
        string calldata vaultId,
        address accessor,
        PermissionLevel minLevel
    ) external view returns (bool ok, uint256 expiry);

    /// @notice Entry preflight, also checking pause, active status, and logic code.
    /// @dev A true result cannot guarantee downstream policy/execution success.
    function canForward(
        uint256 tokenId,
        string calldata vaultId,
        address accessor
    ) external view returns (bool);
    function vaultExists(uint256 tokenId, string calldata vaultId) external view returns (bool);

    /// @notice Monotonic committed ownership/execution epoch. Views never advance it.
    function permissionEpoch(uint256 tokenId) external view returns (uint256);

    /// @notice Raw record, not proof of effective permission. Use checkPermission.
    function getGrant(
        uint256 tokenId,
        string calldata vaultId,
        address grantee
    ) external view returns (Grant memory);

    /// @notice Authenticated call context; all zero fields outside dispatch.
    /// @dev Logic MUST first require msg.sender is its trusted VPM, then verify
    ///      context.logicAddress == address(this) and context.tokenId matches.
    function getForwardingContext() external view returns (ForwardContext memory);
}
