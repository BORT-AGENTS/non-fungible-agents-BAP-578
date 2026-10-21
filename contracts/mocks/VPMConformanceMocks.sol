// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./MockBAP578ForVPM.sol";
import "../extensions/AgentExecutionPermissionManagerReferenceV1.sol";

interface IVPMConformanceContext {
    struct ForwardingContext {
        uint256 tokenId;
        bytes32 vaultIdHash;
        address accessor;
        address logicAddress;
        uint256 ownershipNonce;
        uint256 executionRevision;
    }

    function getForwardingContext() external view returns (ForwardingContext memory);

    function forwardHandleAction(
        uint256 tokenId,
        string calldata vaultId,
        string calldata action,
        bytes calldata data
    ) external returns (bool, bytes memory);
}

/// @notice Test collection whose nonce changes even when ownership round-trips atomically.
contract MockNonceTrackedCollection is MockBAP578ForVPM {
    mapping(uint256 => uint256) public ownershipNonce;

    function mint(uint256 tokenId, address to, address logicAddress) external override {
        ownerOf[tokenId] = to;
        agentStates[tokenId] = AgentState(0, true, logicAddress, block.timestamp);
        ownershipNonce[tokenId]++;
    }

    function transfer(uint256 tokenId, address to) external override {
        ownerOf[tokenId] = to;
        ownershipNonce[tokenId]++;
    }
}

/// @notice Demonstrates why observation cannot detect an intermediate owner after rollback.
contract VPMAtomicRoundTrip {
    function roundTrip(
        MockBAP578ForVPM collection,
        uint256 tokenId,
        address intermediate,
        address original
    ) external {
        collection.transfer(tokenId, intermediate);
        collection.transfer(tokenId, original);
    }

    function roundTripWithRejectedObservation(
        MockBAP578ForVPM collection,
        IVPMConformanceContext vpm,
        uint256 tokenId,
        address intermediate,
        address original
    ) external {
        collection.transfer(tokenId, intermediate);
        (bool accepted, ) = address(vpm).call(
            abi.encodeWithSelector(
                vpm.forwardHandleAction.selector,
                tokenId,
                "default",
                "probe",
                bytes("")
            )
        );
        require(!accepted, "test: stale caller must be rejected");
        collection.transfer(tokenId, original);
    }
}

/// @notice Independently encoded return values and errors test fail-closed ABI handling.
contract VPMRawReturnLogic {
    error ActionDeclined(uint256 reasonCode);

    uint256 public callCount;
    uint8 public mode;
    bool public nestedRejected;
    address public forwarder;

    function configure(uint8 mode_, address forwarder_) external {
        mode = mode_;
        forwarder = forwarder_;
    }

    function handleAction(
        uint256 tokenId,
        string calldata,
        bytes calldata data
    ) external returns (bool success, bytes memory result) {
        callCount++;
        if (mode == 1) return (false, data);
        if (mode == 2) {
            assembly {
                return(0, 0)
            }
        }
        if (mode == 3) {
            assembly {
                mstore(0, 1)
                return(0, 31)
            }
        }
        if (mode == 4) {
            bytes memory malformed = abi.encode(uint256(2), uint256(64), uint256(0));
            assembly {
                return(add(malformed, 32), mload(malformed))
            }
        }
        if (mode == 5) {
            bytes memory malformed = abi.encode(true, type(uint256).max, uint256(0));
            assembly {
                return(add(malformed, 32), mload(malformed))
            }
        }
        if (mode == 6) revert ActionDeclined(17);
        if (mode == 7) {
            uint256 denominator = uint256(uint160(forwarder));
            return (true, abi.encode(uint256(1) / denominator));
        }
        if (mode == 8) {
            assembly {
                revert(0, 0)
            }
        }
        if (mode == 9) {
            (bool accepted, ) = forwarder.call(
                abi.encodeWithSelector(
                    IVPMConformanceContext.forwardHandleAction.selector,
                    tokenId,
                    "default",
                    "nested",
                    bytes("")
                )
            );
            nestedRejected = !accepted;
        }
        if (mode == 10) {
            (bool accepted, ) = forwarder.call(
                abi.encodeWithSignature(
                    "revokePermission(uint256,string,address)",
                    tokenId,
                    "default",
                    address(this)
                )
            );
            nestedRejected = !accepted;
        }
        if (mode == 11) {
            (bool accepted, ) = forwarder.call(
                abi.encodeWithSignature("syncAgentState(uint256)", tokenId)
            );
            nestedRejected = !accepted;
        }
        return (true, data);
    }
}

/// @notice A policy authenticates the live VPM context instead of trusting supplied actors.
contract VPMContextOperatorPolicy {
    IVPMConformanceContext public immutable trustedForwarder;
    address public immutable expectedAccessor;
    bytes32 public immutable expectedVault;

    constructor(address vpm, address accessor, bytes32 vault) {
        trustedForwarder = IVPMConformanceContext(vpm);
        expectedAccessor = accessor;
        expectedVault = vault;
    }

    function authorize(uint256 tokenId) external view {
        IVPMConformanceContext.ForwardingContext memory context = trustedForwarder
            .getForwardingContext();
        require(
            context.logicAddress == msg.sender && msg.sender != address(0),
            "policy: wrong destination"
        );
        require(context.tokenId == tokenId, "policy: wrong token");
        require(context.accessor == expectedAccessor, "policy: wrong accessor");
        require(context.vaultIdHash == expectedVault, "policy: wrong namespace");
    }
}

contract VPMContextPolicyLogic {
    IVPMConformanceContext public immutable trustedForwarder;
    VPMContextOperatorPolicy public immutable policy;
    address public lastAccessor;
    bytes32 public lastVault;
    uint256 public callCount;

    constructor(address vpm, VPMContextOperatorPolicy policy_) {
        trustedForwarder = IVPMConformanceContext(vpm);
        policy = policy_;
    }

    function handleAction(
        uint256 tokenId,
        string calldata,
        bytes calldata data
    ) external returns (bool, bytes memory) {
        require(msg.sender == address(trustedForwarder), "logic: untrusted forwarder");
        IVPMConformanceContext.ForwardingContext memory context = trustedForwarder
            .getForwardingContext();
        require(
            context.logicAddress == address(this) && context.tokenId == tokenId,
            "logic: wrong context"
        );
        policy.authorize(tokenId);
        lastAccessor = context.accessor;
        lastVault = context.vaultIdHash;
        callCount++;
        return (true, data);
    }
}

contract VPMConformanceUpgrade is AgentExecutionPermissionManagerReferenceV1 {
    function conformanceVersion() external pure returns (uint256) {
        return 2;
    }
}

/// @notice ABI-independent resolver fixture for failures and dishonest profile output.
contract VPMConfigurableResolver {
    address public immutable collection;
    bool public immutable supportsOwnershipNonce;
    address public reportedOwner;
    address public reportedLogic;
    bool public reportedActive = true;
    uint256 public reportedNonce;
    uint8 public returnMode;

    constructor(address collection_, address owner_, address logic_, bool supportsNonce_) {
        collection = collection_;
        reportedOwner = owner_;
        reportedLogic = logic_;
        supportsOwnershipNonce = supportsNonce_;
    }

    function supportsExecutionRevision() external pure returns (bool) {
        return false;
    }

    function configureState(address owner_, address logic_, bool active_, uint256 nonce_) external {
        reportedOwner = owner_;
        reportedLogic = logic_;
        reportedActive = active_;
        reportedNonce = nonce_;
    }

    function configureReturn(uint8 mode_) external {
        returnMode = mode_;
    }

    function getAgentState(
        uint256
    ) external view returns (address, address, bool, uint256, uint256) {
        if (returnMode == 1) revert("resolver: unavailable");
        if (returnMode == 2) {
            assembly {
                return(0, 0)
            }
        }
        if (returnMode == 3) {
            bytes memory malformed = abi.encode(
                reportedOwner,
                reportedLogic,
                uint256(2),
                reportedNonce,
                uint256(0)
            );
            assembly {
                return(add(malformed, 32), mload(malformed))
            }
        }
        return (reportedOwner, reportedLogic, reportedActive, reportedNonce, 0);
    }
}
