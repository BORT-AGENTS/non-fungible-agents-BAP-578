// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ERC721 } from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

interface IVPMProfileSync {
    function syncAgentState(uint256 tokenId) external;
}

/// @notice Exercises a real ERC721 receiver callback, including an optional
///         successful VPM observation before transferring the NFT back.
contract VPMTransferBackReceiver is IERC721Receiver {
    IVPMProfileSync public immutable MANAGER;
    bool public immutable SYNC_BEFORE_RETURN;

    constructor(address manager, bool syncBeforeReturn) {
        MANAGER = IVPMProfileSync(manager);
        SYNC_BEFORE_RETURN = syncBeforeReturn;
    }

    function onERC721Received(
        address,
        address from,
        uint256 tokenId,
        bytes calldata
    ) external returns (bytes4) {
        if (SYNC_BEFORE_RETURN) MANAGER.syncAgentState(tokenId);
        IERC721(msg.sender).transferFrom(address(this), from, tokenId);
        return IERC721Receiver.onERC721Received.selector;
    }
}

/// @notice Test-only counter implementation. Its nonce survives burn and remint
///         of a token ID, and its transfer hook runs before receiver callbacks.
contract VPMNonceLifecycleCollection is ERC721 {
    struct AgentState {
        uint256 balance;
        bool active;
        address logicAddress;
        uint256 createdAt;
    }

    mapping(uint256 => AgentState) public agentStates;
    mapping(uint256 => uint256) public ownershipNonce;
    bool public paused;

    constructor() ERC721("Nonce lifecycle fixture", "NLF") {}

    function mint(uint256 tokenId, address to, address logic) external {
        agentStates[tokenId] = AgentState(0, true, logic, block.timestamp);
        _safeMint(to, tokenId);
    }

    function burn(uint256 tokenId) external {
        require(_isApprovedOrOwner(msg.sender, tokenId), "fixture: not authorized");
        _burn(tokenId);
        delete agentStates[tokenId];
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 firstTokenId,
        uint256 batchSize
    ) internal override {
        super._beforeTokenTransfer(from, to, firstTokenId, batchSize);
        for (uint256 i; i < batchSize; ++i) {
            ++ownershipNonce[firstTokenId + i];
        }
    }
}
