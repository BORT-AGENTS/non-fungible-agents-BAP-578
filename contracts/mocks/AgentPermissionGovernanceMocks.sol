// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Test council only, not an audited production multisig. Its profile setter
///      deliberately permits one owner to lower the threshold for adversarial tests.
contract VPMTestCouncil {
    address[] private _owners;
    mapping(address => bool) private _isOwner;
    uint256 private _threshold;
    uint256 public nonce;
    mapping(bytes32 => mapping(address => bool)) private _approved;

    constructor(address[] memory owners_, uint256 threshold_) {
        require(threshold_ != 0 && threshold_ <= owners_.length, "test council: threshold");
        for (uint256 i; i < owners_.length; ++i) {
            require(owners_[i] != address(0) && !_isOwner[owners_[i]], "test council: owner");
            _owners.push(owners_[i]);
            _isOwner[owners_[i]] = true;
        }
        _threshold = threshold_;
    }

    function getOwners() external view returns (address[] memory) {
        return _owners;
    }

    function getThreshold() external view returns (uint256) {
        return _threshold;
    }

    function setThreshold(uint256 threshold_) external {
        require(_isOwner[msg.sender], "test council: owner only");
        require(threshold_ != 0 && threshold_ <= _owners.length, "test council: threshold");
        _threshold = threshold_;
    }

    function approve(address target, bytes calldata data) external {
        require(_isOwner[msg.sender], "test council: owner only");
        _approved[_requestId(target, data)][msg.sender] = true;
    }

    function execute(address target, bytes calldata data) external returns (bytes memory result) {
        bytes32 requestId = _requestId(target, data);
        uint256 approvals;
        for (uint256 i; i < _owners.length; ++i) {
            if (_approved[requestId][_owners[i]]) ++approvals;
        }
        require(approvals >= _threshold, "test council: insufficient approvals");
        ++nonce;
        (bool success, bytes memory returned) = target.call(data);
        if (!success) {
            assembly {
                revert(add(returned, 32), mload(returned))
            }
        }
        return returned;
    }

    function _requestId(address target, bytes calldata data) private view returns (bytes32) {
        return keccak256(abi.encode(address(this), block.chainid, nonce, target, data));
    }
}

/// @dev Arbitrary introspection responses for constructor validation tests.
contract APMInvalidCouncil {
    address[] private _owners;
    uint256 private _threshold;

    constructor(address[] memory owners_, uint256 threshold_) {
        _owners = owners_;
        _threshold = threshold_;
    }

    function getOwners() external view returns (address[] memory) {
        return _owners;
    }

    function getThreshold() external view returns (uint256) {
        return _threshold;
    }
}

contract APMGovernanceTarget {
    address public governance;
    uint256 public value;

    constructor(address governance_) {
        governance = governance_;
    }

    function setValue(uint256 value_) external {
        require(msg.sender == governance, "test target: governance only");
        value = value_;
    }
}

/// @dev Matching metadata is insufficient to authenticate a timelock implementation.
contract APMFakeGovernance {
    function getMinDelay() external pure returns (uint256) {
        return 48 hours;
    }

    function governanceType() external pure returns (bytes32) {
        return keccak256("BAP578.AgentPermissionTimelock.v1");
    }
}

contract APMGovernanceCallbackLogic {
    address private _target;
    bytes private _payload;
    bool public callbackSucceeded;

    function setCallback(address target, bytes calldata payload) external {
        _target = target;
        _payload = payload;
    }

    function handleAction(
        uint256,
        string calldata,
        bytes calldata
    ) external returns (bool, bytes memory) {
        (bool success, bytes memory returned) = _target.call(_payload);
        callbackSucceeded = success;
        return (true, returned);
    }
}
