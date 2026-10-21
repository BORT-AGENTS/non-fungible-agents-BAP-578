// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { OwnableUpgradeable } from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import * as Security from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import { IAgentExecutionPermissionsV1 } from "./IAgentExecutionPermissionsV1.sol";
import { IAgentStateResolver } from "./IAgentStateResolver.sol";
import { AgentPermissionTimelock } from "./governance/AgentPermissionTimelock.sol";
import { AgentPermissionTimelockFactory } from "./governance/AgentPermissionTimelockFactory.sol";
import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

interface ILogicModuleForwardable {
    function handleAction(
        uint256 tokenId,
        string calldata action,
        bytes calldata data
    ) external returns (bool success, bytes memory result);
}

/// @notice Draft reference implementing EXTENSION-README.md. A namespace is a
///         named ACL; action policy remains the bound logic's responsibility.
/// @dev This revision changes storage and semantics. It is a new-deployment draft,
///      not a storage-compatible upgrade for an existing VPM proxy. The global
///      UUPS owner and pinned resolver are trusted by every NFT owner.
contract AgentExecutionPermissionManagerReferenceV1 is
    IAgentExecutionPermissionsV1,
    Initializable,
    OwnableUpgradeable,
    Security.ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    address public bap578;
    mapping(uint256 => mapping(bytes32 => bool)) private _vaults;
    mapping(uint256 => mapping(bytes32 => mapping(address => Grant))) private _grants;
    mapping(uint256 => uint256) private _permissionEpoch;
    mapping(uint256 => address) private _lastSeenOwner;
    IAgentStateResolver public override resolver;
    bool public override ownershipNonceSupported;
    bool public override executionRevisionSupported;
    ProtectionProfile public override protectionProfile;
    bool public override paused;
    address public override pauseGuardian;
    mapping(uint256 => uint256) private _lastSeenNonce;
    mapping(uint256 => uint256) private _lastSeenExecutionRevision;
    mapping(uint256 => address) private _lastSeenLogic;
    mapping(uint256 => mapping(bytes32 => mapping(address => uint256))) private _grantGeneration;
    ForwardContext private _forwardContext;
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    AgentPermissionTimelockFactory private immutable _deploymentGovernanceFactory;
    AgentPermissionTimelockFactory private _initialGovernanceFactory;
    uint256[48] private __gap;

    modifier whenNotPaused() {
        require(!paused, "VPM: paused");
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _deploymentGovernanceFactory = new AgentPermissionTimelockFactory();
        _disableInitializers();
    }

    /// @notice Default strict profile. Unsupported collections cannot fall back.
    function initialize(
        address resolver_,
        address governance_,
        address guardian_
    ) public initializer {
        _initialize(resolver_, governance_, guardian_, ProtectionProfile.STRICT);
    }

    /// @notice Explicit legacy opt-in. Inspect the two capability getters.
    function initializeLegacyCompatibility(
        address resolver_,
        address governance_,
        address guardian_
    ) public initializer {
        _initialize(resolver_, governance_, guardian_, ProtectionProfile.LEGACY_COMPATIBILITY);
    }

    function _initialize(
        address resolver_,
        address governance_,
        address guardian_,
        ProtectionProfile profile_
    ) internal onlyInitializing {
        require(resolver_.code.length > 0, "VPM: resolver has no code");
        require(
            governance_.code.length > 0 && _deploymentGovernanceFactory.isGovernance(governance_),
            "VPM: unregistered governance"
        );
        require(
            AgentPermissionTimelock(payable(governance_)).getMinDelay() >= 2 days,
            "VPM: governance delay too short"
        );
        require(guardian_ != address(0), "VPM: guardian zero");
        __Ownable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        resolver = IAgentStateResolver(resolver_);
        address nft = resolver.collection();
        require(nft.code.length > 0, "VPM: collection has no code");
        bap578 = nft;
        ownershipNonceSupported = resolver.supportsOwnershipNonce();
        executionRevisionSupported = resolver.supportsExecutionRevision();
        require(
            profile_ != ProtectionProfile.STRICT ||
                (ownershipNonceSupported && executionRevisionSupported),
            "VPM: strict counters required"
        );
        protectionProfile = profile_;
        pauseGuardian = guardian_;
        _initialGovernanceFactory = _deploymentGovernanceFactory;
        _transferOwnership(governance_);
        emit PauseGuardianChanged(address(0), guardian_);
    }

    function createVault(
        uint256 tokenId,
        string calldata vaultId,
        string calldata description
    ) external whenNotPaused nonReentrant {
        IAgentStateResolver.AgentState memory state = _readState(tokenId);
        require(state.owner == msg.sender, "VPM: only NFT owner");
        _syncAgentState(tokenId, state);
        require(bytes(vaultId).length > 0, "VPM: empty vault ID");
        bytes32 vid = _vid(vaultId);
        require(!_vaults[tokenId][vid], "VPM: vault exists");
        _vaults[tokenId][vid] = true;
        emit VaultCreated(tokenId, vid, vaultId, msg.sender, description);
    }

    function grantPermission(
        uint256 tokenId,
        string calldata vaultId,
        address grantee,
        PermissionLevel level,
        uint256 expiry,
        string calldata description
    ) external whenNotPaused nonReentrant {
        require(grantee != address(0), "VPM: grantee zero");
        require(grantee != msg.sender, "VPM: cannot grant to self");
        require(level != PermissionLevel.NONE, "VPM: NONE; use revoke");
        require(expiry == 0 || expiry > block.timestamp, "VPM: expiry in past");
        bytes32 vid = _vid(vaultId);
        require(_vaults[tokenId][vid], "VPM: no such vault");
        IAgentStateResolver.AgentState memory state = _readState(tokenId);
        uint256 epoch = _syncAgentState(tokenId, state);
        require(grantee != state.owner, "VPM: owner has implicit access");

        address parentAdmin;
        uint256 parentGeneration;
        if (msg.sender != state.owner) {
            require(level != PermissionLevel.ADMIN, "VPM: only owner grants ADMIN");
            (bool isAdmin, ) = _check(tokenId, vid, msg.sender, PermissionLevel.ADMIN, state);
            require(isAdmin, "VPM: not owner or admin");
            _requireOwnChildOrStale(tokenId, vid, grantee, epoch);
            Grant storage parent = _grants[tokenId][vid][msg.sender];
            require(
                parent.expiry == 0 || (expiry != 0 && expiry <= parent.expiry),
                "VPM: child outlives ADMIN"
            );
            parentAdmin = msg.sender;
            parentGeneration = parent.generation;
        }

        uint256 generation = ++_grantGeneration[tokenId][vid][grantee];
        _grants[tokenId][vid][grantee] = Grant({
            level: level,
            expiry: expiry,
            epoch: epoch,
            parentAdmin: parentAdmin,
            parentGeneration: parentGeneration,
            generation: generation,
            exists: true
        });
        emit PermissionGranted(
            tokenId,
            vid,
            grantee,
            level,
            expiry,
            description,
            msg.sender,
            generation,
            parentAdmin,
            parentGeneration
        );
    }

    function revokePermission(
        uint256 tokenId,
        string calldata vaultId,
        address grantee
    ) external nonReentrant {
        bytes32 vid = _vid(vaultId);
        Grant storage target = _grants[tokenId][vid][grantee];
        require(target.exists, "VPM: no such grant");
        IAgentStateResolver.AgentState memory state = _readState(tokenId);
        uint256 epoch = _syncAgentState(tokenId, state);
        if (msg.sender != state.owner) {
            (bool isAdmin, ) = _check(tokenId, vid, msg.sender, PermissionLevel.ADMIN, state);
            require(isAdmin, "VPM: not owner or admin");
            if (grantee != msg.sender) {
                require(
                    target.epoch == epoch && target.parentAdmin == msg.sender,
                    "VPM: not own child"
                );
            }
        }
        ++_grantGeneration[tokenId][vid][grantee];
        delete _grants[tokenId][vid][grantee];
        emit PermissionRevoked(tokenId, vid, grantee);
    }

    function forwardHandleAction(
        uint256 tokenId,
        string calldata vaultId,
        string calldata action,
        bytes calldata data
    ) external whenNotPaused nonReentrant returns (bool success, bytes memory result) {
        bytes32 vid = _vid(vaultId);
        require(_vaults[tokenId][vid], "VPM: no such vault");
        IAgentStateResolver.AgentState memory state = _readState(tokenId);
        _syncAgentState(tokenId, state);
        (bool ok, ) = _check(tokenId, vid, msg.sender, PermissionLevel.WRITE, state);
        require(ok, "VPM: caller lacks WRITE");
        require(state.active, "VPM: agent inactive");
        require(state.logicAddress != address(0), "VPM: no logic bound");
        require(state.logicAddress.code.length > 0, "VPM: logic has no code");

        _forwardContext = ForwardContext(
            tokenId,
            vid,
            msg.sender,
            state.logicAddress,
            state.ownershipNonce,
            state.executionRevision
        );
        emit ActionForwarded(tokenId, vid, msg.sender, action);
        (success, result) = ILogicModuleForwardable(state.logicAddress).handleAction(
            tokenId,
            action,
            data
        );
        delete _forwardContext;
        emit ActionResult(tokenId, vid, msg.sender, state.logicAddress, success, keccak256(result));
    }

    function syncAgentState(uint256 tokenId) external nonReentrant {
        _syncAgentState(tokenId, _readState(tokenId));
    }

    function resetPermissions(uint256 tokenId) external nonReentrant {
        IAgentStateResolver.AgentState memory state = _readState(tokenId);
        require(state.owner == msg.sender, "VPM: only NFT owner");
        _syncAgentState(tokenId, state);
        uint256 epoch = ++_permissionEpoch[tokenId];
        emit PermissionsReset(tokenId, msg.sender, epoch);
    }

    function pause() external nonReentrant {
        require(msg.sender == pauseGuardian || msg.sender == owner(), "VPM: not pause authority");
        paused = true;
        emit ManagerPauseChanged(true, msg.sender);
    }

    function unpause() external onlyOwner nonReentrant {
        paused = false;
        emit ManagerPauseChanged(false, msg.sender);
    }

    function setPauseGuardian(address guardian_) external onlyOwner nonReentrant {
        require(guardian_ != address(0), "VPM: guardian zero");
        address previous = pauseGuardian;
        pauseGuardian = guardian_;
        emit PauseGuardianChanged(previous, guardian_);
    }

    /// @dev The concrete delayed governor remains pinned for this implementation.
    ///      A deliberately scheduled implementation replacement can change rules.
    function transferOwnership(address) public view override onlyOwner {
        revert("VPM: governance is pinned");
    }

    function renounceOwnership() public view override onlyOwner {
        revert("VPM: governance is pinned");
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return
            interfaceId == type(IAgentExecutionPermissionsV1).interfaceId ||
            interfaceId == type(IERC165).interfaceId;
    }

    function extensionId() external pure returns (bytes32) {
        return keccak256("bap578.agent-execution-permissions.v1");
    }

    function extensionVersion() external pure returns (uint256) {
        return 1;
    }

    function governance() external view returns (address) {
        return owner();
    }

    /// @notice The factory that authenticated this proxy's initial governor.
    /// @dev Before initialization (including on the locked implementation), this
    ///      returns the implementation's deployment factory for setup tooling.
    function governanceFactory() external view returns (AgentPermissionTimelockFactory) {
        return
            address(_initialGovernanceFactory) == address(0)
                ? _deploymentGovernanceFactory
                : _initialGovernanceFactory;
    }

    function governanceMinDelay() external view returns (uint256) {
        return AgentPermissionTimelock(payable(owner())).getMinDelay();
    }

    function governanceProfile() external pure returns (bytes32) {
        return keccak256("BAP578.AgentPermissionTimelock.v1");
    }

    function checkPermission(
        uint256 tokenId,
        string calldata vaultId,
        address accessor,
        PermissionLevel minLevel
    ) external view returns (bool ok, uint256 expiry) {
        return _check(tokenId, _vid(vaultId), accessor, minLevel, _readState(tokenId));
    }

    function canForward(
        uint256 tokenId,
        string calldata vaultId,
        address accessor
    ) external view returns (bool) {
        if (paused) return false;
        IAgentStateResolver.AgentState memory state = _readState(tokenId);
        if (!state.active || state.logicAddress.code.length == 0) return false;
        (bool ok, ) = _check(tokenId, _vid(vaultId), accessor, PermissionLevel.WRITE, state);
        return ok;
    }

    function vaultExists(uint256 tokenId, string calldata vaultId) external view returns (bool) {
        return _vaults[tokenId][_vid(vaultId)];
    }

    function permissionEpoch(uint256 tokenId) external view returns (uint256) {
        return _permissionEpoch[tokenId];
    }

    function collection() external view returns (address) {
        return bap578;
    }

    function getGrant(
        uint256 tokenId,
        string calldata vaultId,
        address grantee
    ) external view returns (Grant memory grant) {
        bytes32 vid = _vid(vaultId);
        grant = _grants[tokenId][vid][grantee];
        grant.generation = _grantGeneration[tokenId][vid][grantee];
    }

    function getForwardingContext() external view returns (ForwardContext memory) {
        return _forwardContext;
    }

    function _readState(
        uint256 tokenId
    ) internal view returns (IAgentStateResolver.AgentState memory state) {
        state = resolver.getAgentState(tokenId);
        require(state.owner != address(0), "VPM: unknown token");
        require(
            ownershipNonceSupported || state.ownershipNonce == 0,
            "VPM: unexpected ownership nonce"
        );
        require(
            executionRevisionSupported || state.executionRevision == 0,
            "VPM: unexpected execution revision"
        );
        if (ownershipNonceSupported && _lastSeenOwner[tokenId] != address(0)) {
            require(
                state.ownershipNonce >= _lastSeenNonce[tokenId],
                "VPM: ownership nonce decreased"
            );
            require(
                state.owner == _lastSeenOwner[tokenId] ||
                    state.ownershipNonce > _lastSeenNonce[tokenId],
                "VPM: unchanged ownership nonce"
            );
        }
        if (executionRevisionSupported && _lastSeenOwner[tokenId] != address(0)) {
            require(
                state.executionRevision >= _lastSeenExecutionRevision[tokenId],
                "VPM: execution revision decreased"
            );
            require(
                state.logicAddress == _lastSeenLogic[tokenId] ||
                    state.executionRevision > _lastSeenExecutionRevision[tokenId],
                "VPM: unchanged execution revision"
            );
        }
    }

    function _stateUnchanged(
        uint256 tokenId,
        IAgentStateResolver.AgentState memory state
    ) internal view returns (bool) {
        return
            _lastSeenOwner[tokenId] == state.owner &&
            (!ownershipNonceSupported || _lastSeenNonce[tokenId] == state.ownershipNonce) &&
            _lastSeenLogic[tokenId] == state.logicAddress &&
            (!executionRevisionSupported ||
                _lastSeenExecutionRevision[tokenId] == state.executionRevision);
    }

    function _syncAgentState(
        uint256 tokenId,
        IAgentStateResolver.AgentState memory state
    ) internal returns (uint256) {
        address previous = _lastSeenOwner[tokenId];
        if (previous == address(0)) {
            _lastSeenOwner[tokenId] = state.owner;
            _lastSeenNonce[tokenId] = state.ownershipNonce;
            _lastSeenLogic[tokenId] = state.logicAddress;
            _lastSeenExecutionRevision[tokenId] = state.executionRevision;
        } else if (!_stateUnchanged(tokenId, state)) {
            uint256 epoch = ++_permissionEpoch[tokenId];
            _lastSeenOwner[tokenId] = state.owner;
            _lastSeenNonce[tokenId] = state.ownershipNonce;
            _lastSeenLogic[tokenId] = state.logicAddress;
            _lastSeenExecutionRevision[tokenId] = state.executionRevision;
            emit AgentEpochAdvanced(tokenId, previous, state.owner, epoch);
        }
        return _permissionEpoch[tokenId];
    }

    function _check(
        uint256 tokenId,
        bytes32 vid,
        address accessor,
        PermissionLevel minLevel,
        IAgentStateResolver.AgentState memory state
    ) internal view returns (bool ok, uint256 expiry) {
        if (!_vaults[tokenId][vid]) return (false, 0);
        if (accessor == state.owner) return (true, 0);
        Grant storage grant = _grants[tokenId][vid][accessor];
        expiry = grant.expiry;
        uint256 epoch = _permissionEpoch[tokenId];
        if (!_stateUnchanged(tokenId, state) || !_validGrant(grant, epoch)) return (false, expiry);
        if (uint8(grant.level) < uint8(minLevel)) return (false, expiry);
        if (grant.parentAdmin != address(0)) {
            Grant storage parent = _grants[tokenId][vid][grant.parentAdmin];
            if (
                !_validGrant(parent, epoch) ||
                parent.level != PermissionLevel.ADMIN ||
                parent.parentAdmin != address(0) ||
                parent.generation != grant.parentGeneration
            ) return (false, expiry);
        }
        return (true, expiry);
    }

    function _validGrant(Grant storage grant, uint256 epoch) internal view returns (bool) {
        return
            grant.exists &&
            grant.epoch == epoch &&
            (grant.expiry == 0 || block.timestamp <= grant.expiry);
    }

    function _requireOwnChildOrStale(
        uint256 tokenId,
        bytes32 vid,
        address grantee,
        uint256 epoch
    ) internal view {
        Grant storage target = _grants[tokenId][vid][grantee];
        require(
            !target.exists || target.epoch != epoch || target.parentAdmin == msg.sender,
            "VPM: not own child"
        );
    }

    function _vid(string calldata vaultId) internal pure returns (bytes32) {
        return keccak256(bytes(vaultId));
    }
    function _authorizeUpgrade(address) internal view override onlyOwner {
        require(!_reentrancyGuardEntered(), "VPM: dispatch in progress");
    }
}
