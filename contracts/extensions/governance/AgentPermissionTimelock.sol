// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { TimelockController } from "@openzeppelin/contracts/governance/TimelockController.sol";

interface IAgentPermissionCouncil {
    function getThreshold() external view returns (uint256);

    function getOwners() external view returns (address[] memory);
}

/// @notice Self-administered governance for the upgradeable execution-permission reference.
/// @dev Proposers MUST expose a Safe-compatible, at-least-two-owner threshold profile.
///      This configuration check does not establish that the code enforces that policy.
///      Deployers must independently verify the council implementation and upgrade path.
///      The concrete factory records only timelocks it successfully creates.
contract AgentPermissionTimelock is TimelockController {
    uint256 public constant MINIMUM_DELAY = 48 hours;
    bytes32 public constant GOVERNANCE_TYPE = keccak256("BAP578.AgentPermissionTimelock.v1");

    // The parent field is private. Both its public getter and updater are overridden
    // so every inherited scheduling path uses this floor-checked authoritative value.
    uint256 private _referenceMinDelay;

    constructor(
        uint256 initialDelay,
        address proposerContract
    ) TimelockController(initialDelay, _single(proposerContract), _single(address(0)), address(0)) {
        require(initialDelay >= MINIMUM_DELAY, "APM governance: delay below floor");
        _validateCouncil(proposerContract);
        _referenceMinDelay = initialDelay;
    }

    function governanceType() external pure returns (bytes32) {
        return GOVERNANCE_TYPE;
    }

    function getMinDelay() public view override returns (uint256) {
        return _referenceMinDelay;
    }

    /// @dev Revalidate so a council threshold reduction blocks new proposals.
    function schedule(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) public override {
        _validateCouncil(msg.sender);
        super.schedule(target, value, data, predecessor, salt, delay);
    }

    function scheduleBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) public override {
        _validateCouncil(msg.sender);
        super.scheduleBatch(targets, values, payloads, predecessor, salt, delay);
    }

    /// @notice Delay changes are themselves delayed, and can never lower the floor.
    function updateDelay(uint256 newDelay) external override {
        require(msg.sender == address(this), "TimelockController: caller must be timelock");
        require(newDelay >= MINIMUM_DELAY, "APM governance: delay below floor");
        emit MinDelayChange(_referenceMinDelay, newDelay);
        _referenceMinDelay = newDelay;
    }

    /// @dev Even delayed role changes cannot create an external, immediate role admin.
    function _grantRole(bytes32 role, address account) internal override {
        require(role != DEFAULT_ADMIN_ROLE, "APM governance: unused admin role");
        require(
            role != TIMELOCK_ADMIN_ROLE || account == address(this),
            "APM governance: admin must be self"
        );
        if (role == PROPOSER_ROLE) _validateCouncil(account);
        super._grantRole(role, account);
    }

    /// @dev Preserve the self-admin path rather than permitting accidental removal.
    function _revokeRole(bytes32 role, address account) internal override {
        require(
            role != TIMELOCK_ADMIN_ROLE || account != address(this),
            "APM governance: self admin required"
        );
        super._revokeRole(role, account);
    }

    function _single(address account) private pure returns (address[] memory accounts) {
        accounts = new address[](1);
        accounts[0] = account;
    }

    function _validateCouncil(address account) private view {
        require(account.code.length != 0, "APM governance: proposer must be contract");
        uint256 threshold = IAgentPermissionCouncil(account).getThreshold();
        address[] memory owners = IAgentPermissionCouncil(account).getOwners();
        require(
            threshold >= 2 && threshold <= owners.length && owners.length <= 256,
            "APM governance: invalid council threshold"
        );
        for (uint256 i; i < owners.length; ++i) {
            require(owners[i] != address(0), "APM governance: zero council owner");
            for (uint256 j; j < i; ++j) {
                require(owners[i] != owners[j], "APM governance: duplicate council owner");
            }
        }
    }
}
