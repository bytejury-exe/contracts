// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IReportHook} from "../../src/interfaces/IReportHook.sol";

/// @dev ERC-1271 smart wallet with a single EOA signer.
contract MockERC1271Wallet is IERC1271 {
    address public immutable signer;

    constructor(address signer_) {
        signer = signer_;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        return err == ECDSA.RecoverError.NoError && recovered == signer ? IERC1271.isValidSignature.selector : bytes4(0);
    }

    function approve(IERC20 token, address spender, uint256 amount) external {
        token.approve(spender, amount);
    }
}

/// @dev Minimal ERC-8004 Identity Registry stand-in (ERC-721, register(agentURI)).
contract MockIdentityRegistry is ERC721 {
    uint256 public lastId;
    mapping(uint256 => string) public agentURI;

    constructor() ERC721("AgentIdentity", "AGENT") {}

    function register(string calldata uri) external returns (uint256 agentId) {
        agentId = lastId++;
        agentURI[agentId] = uri;
        _mint(msg.sender, agentId);
    }
}

/// @dev Report hook that always reverts.
contract RevertingHook is IReportHook {
    function onReportPublished(uint256, bytes32, string calldata, bytes32, uint8, uint8, bytes calldata) external pure {
        revert("hook down");
    }
}

/// @dev Report hook that burns all gas it gets.
contract GasGuzzlerHook is IReportHook {
    uint256 public sink;

    function onReportPublished(uint256, bytes32, string calldata, bytes32, uint8, uint8, bytes calldata) external {
        while (true) {
            ++sink;
        }
    }
}
