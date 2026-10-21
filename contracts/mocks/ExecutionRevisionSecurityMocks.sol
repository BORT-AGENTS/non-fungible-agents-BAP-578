// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ERC721 } from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { IAgentStateResolver } from "../extensions/IAgentStateResolver.sol";
import { IAgentExecutionPermissionsV1 } from "../extensions/IAgentExecutionPermissionsV1.sol";
import { IVaultPermissionManager } from "../extensions/IVaultPermissionManager.sol";

/// @notice Test-only collection implementing actual ERC721 transfer hooks and version counters.
contract RevisionTrackedERC721 is ERC721 {
    struct AgentExecutionState {
        uint256 balance;
        bool active;
        address logicAddress;
        uint256 createdAt;
    }

    address public immutable TEST_CONTROLLER;
    mapping(uint256 => AgentExecutionState) public agentStates;
    mapping(uint256 => uint256) public ownershipNonce;
    mapping(uint256 => uint256) public executionRevision;
    bool public paused;
    bool internal _suppressNonce;

    constructor() ERC721("Revision fixture", "REV") {
        TEST_CONTROLLER = msg.sender;
    }

    function mint(uint256 tokenId, address to, address logic) external {
        require(msg.sender == TEST_CONTROLLER, "fixture: mint controller");
        _mint(to, tokenId);
        agentStates[tokenId] = AgentExecutionState(0, true, logic, block.timestamp);
        ++executionRevision[tokenId];
    }

    function burn(uint256 tokenId) external {
        require(ownerOf(tokenId) == msg.sender, "fixture: NFT owner");
        _burn(tokenId);
        delete agentStates[tokenId];
        ++executionRevision[tokenId];
    }

    function setLogic(uint256 tokenId, address logic) external {
        require(ownerOf(tokenId) == msg.sender, "fixture: NFT owner");
        agentStates[tokenId].logicAddress = logic;
        ++executionRevision[tokenId];
    }

    function roundTripLogic(uint256 tokenId, address intermediate) external {
        require(ownerOf(tokenId) == msg.sender, "fixture: NFT owner");
        address original = agentStates[tokenId].logicAddress;
        agentStates[tokenId].logicAddress = intermediate;
        ++executionRevision[tokenId];
        agentStates[tokenId].logicAddress = original;
        ++executionRevision[tokenId];
    }

    function roundTripOwner(uint256 tokenId, address intermediate) external {
        require(ownerOf(tokenId) == msg.sender, "fixture: NFT owner");
        _transfer(msg.sender, intermediate, tokenId);
        _transfer(intermediate, msg.sender, tokenId);
    }

    function upgradeExecutionModule(uint256 tokenId, address implementation) external {
        require(ownerOf(tokenId) == msg.sender, "fixture: NFT owner");
        RevisionTrackedModuleProxy proxy = RevisionTrackedModuleProxy(
            payable(agentStates[tokenId].logicAddress)
        );
        require(proxy.COLLECTION() == address(this), "fixture: wrong collection");
        require(proxy.TOKEN_ID() == tokenId, "fixture: wrong token");
        ++executionRevision[tokenId];
        proxy.upgradeTo(implementation);
    }

    function _afterTokenTransfer(
        address from,
        address to,
        uint256 firstTokenId,
        uint256 batchSize
    ) internal override {
        super._afterTokenTransfer(from, to, firstTokenId, batchSize);
        if (!_suppressNonce) {
            for (uint256 i; i < batchSize; ++i) ++ownershipNonce[firstTokenId + i];
        }
    }
}

/// @notice Deliberately broken trusted collection used to prove detectable violations fail closed.
contract FaultInjectedRevisionERC721 is RevisionTrackedERC721 {
    function setCountersForTest(uint256 tokenId, uint256 nonce, uint256 revision) external {
        require(msg.sender == TEST_CONTROLLER, "fixture: test controller");
        ownershipNonce[tokenId] = nonce;
        executionRevision[tokenId] = revision;
    }

    function setLogicWithoutRevisionForTest(uint256 tokenId, address logic) external {
        require(msg.sender == TEST_CONTROLLER, "fixture: test controller");
        agentStates[tokenId].logicAddress = logic;
    }

    function transferWithoutNonceForTest(uint256 tokenId, address to) external {
        require(msg.sender == TEST_CONTROLLER, "fixture: test controller");
        _suppressNonce = true;
        _transfer(ownerOf(tokenId), to, tokenId);
        _suppressNonce = false;
    }
}

/// @notice The actual implementation upgrade authority is the collection, not a separate admin.
contract RevisionTrackedModuleProxy is ERC1967Proxy {
    address public immutable COLLECTION;
    uint256 public immutable TOKEN_ID;

    constructor(
        address implementation,
        address collection_,
        uint256 tokenId_
    ) ERC1967Proxy(implementation, "") {
        COLLECTION = collection_;
        TOKEN_ID = tokenId_;
    }

    function upgradeTo(address implementation) external {
        require(msg.sender == COLLECTION, "fixture: collection upgrade controller");
        _upgradeTo(implementation);
    }
}

contract RevisionModuleV1 {
    function version() external pure virtual returns (uint256) {
        return 1;
    }

    function handleAction(
        uint256,
        string calldata,
        bytes calldata data
    ) external pure returns (bool, bytes memory) {
        return (true, data);
    }
}

contract RevisionModuleV2 is RevisionModuleV1 {
    function version() external pure override returns (uint256) {
        return 2;
    }
}

contract RevisionContextLogic {
    IAgentExecutionPermissionsV1 public immutable MANAGER;
    uint256 public lastOwnershipNonce;
    uint256 public lastExecutionRevision;

    constructor(address manager) {
        MANAGER = IAgentExecutionPermissionsV1(manager);
    }

    function handleAction(
        uint256 tokenId,
        string calldata,
        bytes calldata data
    ) external returns (bool, bytes memory) {
        require(msg.sender == address(MANAGER), "fixture: trusted manager");
        IAgentExecutionPermissionsV1.ForwardContext memory context = MANAGER.getForwardingContext();
        require(
            context.tokenId == tokenId && context.logicAddress == address(this),
            "fixture: context"
        );
        lastOwnershipNonce = context.ownershipNonce;
        lastExecutionRevision = context.executionRevision;
        return (true, data);
    }
}

contract ExecutionRevisionOnlyResolver is IAgentStateResolver {
    IAgentStateResolver public immutable SOURCE;
    address public immutable override collection;

    constructor(address source) {
        SOURCE = IAgentStateResolver(source);
        collection = SOURCE.collection();
    }

    function supportsOwnershipNonce() external pure returns (bool) {
        return false;
    }

    function supportsExecutionRevision() external pure returns (bool) {
        return true;
    }

    function getAgentState(uint256 tokenId) external view returns (AgentState memory state) {
        state = SOURCE.getAgentState(tokenId);
        state.ownershipNonce = 0;
        state.executionRevision = RevisionTrackedERC721(collection).executionRevision(tokenId);
    }
}

/// @notice The enums and interface identifiers are independently visible to tests.
contract PermissionInterfaceIdentityProbe {
    function executionInterfaceId() external pure returns (bytes4) {
        return type(IAgentExecutionPermissionsV1).interfaceId;
    }

    function dataAccessInterfaceId() external pure returns (bytes4) {
        return type(IVaultPermissionManager).interfaceId;
    }

    function executionEnums() external pure returns (uint8, uint8, uint8, uint8) {
        return (
            uint8(IAgentExecutionPermissionsV1.PermissionLevel.NONE),
            uint8(IAgentExecutionPermissionsV1.PermissionLevel.READ),
            uint8(IAgentExecutionPermissionsV1.PermissionLevel.WRITE),
            uint8(IAgentExecutionPermissionsV1.PermissionLevel.ADMIN)
        );
    }

    function dataAccessEnums() external pure returns (uint8, uint8, uint8, uint8) {
        return (
            uint8(IVaultPermissionManager.PermissionLevel.READ_ONLY),
            uint8(IVaultPermissionManager.PermissionLevel.WRITE),
            uint8(IVaultPermissionManager.PermissionLevel.ADMIN),
            uint8(IVaultPermissionManager.PermissionLevel.FULL_CONTROL)
        );
    }
}
