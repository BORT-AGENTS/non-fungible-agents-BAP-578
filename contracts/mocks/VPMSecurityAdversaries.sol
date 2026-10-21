// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IAgentExecutionPermissionsV1 } from "../extensions/IAgentExecutionPermissionsV1.sol";
import { MockBAP578ForVPM } from "./MockBAP578ForVPM.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @notice A callback can read public context but cannot use it as a bearer credential.
contract VPMContextCallbackProbe {
    bool public observedLiveContext;
    bool public directActionAccepted;
    bool public nestedForwardAccepted;
    bool public policyAccepted;

    function attack(address manager, address logic, address policy, uint256 tokenId) external {
        IAgentExecutionPermissionsV1 vpm = IAgentExecutionPermissionsV1(manager);
        IAgentExecutionPermissionsV1.ForwardContext memory context = vpm.getForwardingContext();
        observedLiveContext = context.logicAddress == logic && context.tokenId == tokenId;
        (directActionAccepted, ) = logic.call(
            abi.encodeWithSignature(
                "handleAction(uint256,string,bytes)",
                tokenId,
                "callback",
                bytes("")
            )
        );
        (nestedForwardAccepted, ) = manager.call(
            abi.encodeWithSelector(
                vpm.forwardHandleAction.selector,
                tokenId,
                "default",
                "callback",
                bytes("")
            )
        );
        (policyAccepted, ) = policy.call(abi.encodeWithSignature("authorize(uint256)", tokenId));
    }
}

/// @notice Deliberately adversarial actions test the documented external-call boundary.
contract VPMExternalBoundaryLogic {
    IAgentExecutionPermissionsV1 public immutable trustedForwarder;
    address public immutable callback;
    address public immutable policy;
    address public lastAccessor;
    address public lastContextLogic;
    uint256 public callCount;

    constructor(address manager, address callback_, address policy_) {
        trustedForwarder = IAgentExecutionPermissionsV1(manager);
        callback = callback_;
        policy = policy_;
    }

    function handleAction(
        uint256 tokenId,
        string calldata action,
        bytes calldata data
    ) external returns (bool, bytes memory) {
        require(msg.sender == address(trustedForwarder), "boundary: untrusted forwarder");
        IAgentExecutionPermissionsV1.ForwardContext memory context = trustedForwarder
            .getForwardingContext();
        require(context.logicAddress == address(this), "boundary: wrong destination");
        require(context.tokenId == tokenId, "boundary: wrong token");
        lastAccessor = context.accessor;
        lastContextLogic = context.logicAddress;
        callCount++;
        bytes32 command = keccak256(bytes(action));
        if (command == keccak256("callback")) {
            VPMContextCallbackProbe(callback).attack(
                address(trustedForwarder),
                address(this),
                policy,
                tokenId
            );
        } else if (command == keccak256("change-owner")) {
            (address nft, address newOwner) = abi.decode(data, (address, address));
            // The unrestricted test mock stands in for a collection that separately
            // authorizes the module. VPM itself grants no ERC-721 transfer right.
            MockBAP578ForVPM(nft).transfer(tokenId, newOwner);
            require(
                !trustedForwarder.canForward(tokenId, "default", context.accessor),
                "boundary: stale still valid"
            );
            require(
                trustedForwarder.getForwardingContext().accessor == context.accessor,
                "boundary: lost snapshot"
            );
        }
        return (true, data);
    }
}

contract VPMBoundaryLogicProxy is ERC1967Proxy {
    constructor(address implementation) ERC1967Proxy(implementation, bytes("")) {}
}

/// @notice Supplies forged context while calling from a different forwarder address.
contract VPMContextSpoofingForwarder {
    IAgentExecutionPermissionsV1.ForwardContext private _context;

    function impersonate(
        address logic,
        uint256 tokenId,
        address accessor
    ) external returns (bool accepted) {
        _context = IAgentExecutionPermissionsV1.ForwardContext(
            tokenId,
            keccak256("default"),
            accessor,
            logic,
            0,
            0
        );
        (accepted, ) = logic.call(
            abi.encodeWithSignature(
                "handleAction(uint256,string,bytes)",
                tokenId,
                "probe",
                bytes("")
            )
        );
    }

    function getForwardingContext()
        external
        view
        returns (IAgentExecutionPermissionsV1.ForwardContext memory)
    {
        return _context;
    }
}

/// @notice Raw EVM return values separate Solidity decoder acceptance from strict ABI encoding.
contract VPMHostileReturnLogic {
    uint8 public mode;
    uint256 public callCount;

    function configure(uint8 value) external {
        mode = value;
    }

    function handleAction(
        uint256,
        string calldata,
        bytes calldata
    ) external returns (bool, bytes memory) {
        callCount++;
        uint8 response = mode;
        if (response == 1) {
            // Offset zero aliases the first head word as a one-byte length.
            // Solidity's non-strict decoder accepts this as (true, hex"00").
            assembly {
                mstore(0, 1)
                mstore(32, 0)
                return(0, 64)
            }
        }
        if (response == 2) {
            // A canonical empty result followed by an unused extra word.
            assembly {
                mstore(0, 1)
                mstore(32, 64)
                mstore(64, 0)
                mstore(96, 0xdeadbeef)
                return(0, 128)
            }
        }
        if (response == 3) {
            // Allocating one MiB can succeed in the callee yet exhaust the caller
            // while it copies returndata. All state must still roll back.
            assembly {
                return(0, 0x100000)
            }
        }
        if (response == 4) {
            assembly {
                revert(0, 0x100000)
            }
        }
        return (true, bytes(""));
    }
}

/// @notice Matching selectors do not make a state-writing resolver a safe view.
contract VPMStateWritingResolver {
    address public immutable collection;
    address public immutable reportedOwner;
    address public immutable reportedLogic;
    uint256 public writes;

    constructor(address nft, address owner_, address logic_) {
        collection = nft;
        reportedOwner = owner_;
        reportedLogic = logic_;
    }

    function supportsOwnershipNonce() external pure returns (bool) {
        return false;
    }

    function supportsExecutionRevision() external pure returns (bool) {
        return false;
    }

    // Intentionally not view: VPM's independently declared interface must force
    // STATICCALL and reject this implementation before any authority is stored.
    function getAgentState(uint256) external returns (address, address, bool, uint256, uint256) {
        writes++;
        return (reportedOwner, reportedLogic, true, 0, 0);
    }
}
