// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title BAP-578 section 4.6 off-chain data permission interface
/// @notice Preserves the interface published in the BNB Chain BAP-578 draft.
/// @dev This API authorizes off-chain data access. On-chain execution delegation
///      is a separate extension, IAgentExecutionPermissionsV1. Their enum values,
///      selectors and authorization meanings MUST NOT be cast or substituted.
///      This declaration is not an implementation of signature validation or an
///      adapter between the two permission systems.
interface IVaultPermissionManager {
    enum PermissionLevel {
        READ_ONLY,
        WRITE,
        ADMIN,
        FULL_CONTROL
    }

    struct Permission {
        address delegate;
        PermissionLevel level;
        uint256 expiryTime;
        bool isActive;
    }

    function delegateAccess(
        uint256 tokenId,
        address delegate,
        PermissionLevel level,
        uint256 expiryTime,
        bytes memory signature
    ) external;

    function revokeAccess(uint256 tokenId, address delegate) external;

    function verifyAccess(
        uint256 tokenId,
        address accessor,
        PermissionLevel requiredLevel
    ) external view returns (bool);
}
