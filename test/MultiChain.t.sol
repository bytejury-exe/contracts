// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseTest} from "./Base.t.sol";
import {ScanPayments} from "../src/ScanPayments.sol";

/// @notice Scan targets on other chains (payments stay on Robinhood). Targets are opaque strings: no 0x / case rules.
contract MultiChainTest is BaseTest {
    string internal constant SOLANA = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
    string internal constant SOL_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"; // base58, mixed case

    event ScanRequested(
        uint256 indexed scanId,
        address indexed payer,
        bytes32 indexed targetKey,
        string chain,
        string target,
        address token,
        uint256 amountReceived,
        uint256 burned,
        uint256 toTreasury
    );

    function _chains() internal pure returns (string[4] memory) {
        return ["eip155:1", "eip155:42161", "eip155:8453", SOLANA];
    }

    function _enableAll() internal {
        string[4] memory chains = _chains();
        vm.startPrank(owner);
        for (uint256 i; i < 4; ++i) {
            sp.setChainConfig(chains[i], true, 0);
        }
        vm.stopPrank();
    }

    function test_NewChains_UnsupportedUntilEnabled() public {
        string[4] memory chains = _chains();
        vm.startPrank(user);
        token.approve(address(sp), PRICE);
        for (uint256 i; i < 4; ++i) {
            vm.expectRevert(abi.encodeWithSelector(ScanPayments.UnsupportedChain.selector, chains[i]));
            sp.requestScan(chains[i], TARGET);
        }
        vm.stopPrank();
    }

    function test_EachNewChain_QuoteTargetKeyRequestScan() public {
        _enableAll();
        string[4] memory chains = _chains();
        for (uint256 i; i < 4; ++i) {
            string memory target = i == 3 ? SOL_MINT : TARGET;
            assertEq(sp.quote(user, chains[i], target), PRICE);
            bytes32 key = sp.targetKey(chains[i], target);
            assertEq(key, keccak256(abi.encodePacked(chains[i], ":", target)));
            vm.startPrank(user);
            token.approve(address(sp), PRICE);
            vm.expectEmit(address(sp));
            emit ScanRequested(i + 1, user, key, chains[i], target, address(token), PRICE, PRICE / 2, PRICE / 2);
            uint256 id = sp.requestScan(chains[i], target);
            vm.stopPrank();
            assertEq(sp.scanTarget(id), key);
        }
        (string[] memory listed,) = sp.getChains();
        assertEq(listed.length, 5, "home chain + 4 scan chains");
    }

    function test_SolanaTarget_IsCaseSensitive() public {
        _enableAll();
        string memory lower = vm.toLowercase(SOL_MINT);
        assertTrue(sp.targetKey(SOLANA, SOL_MINT) != sp.targetKey(SOLANA, lower), "base58 must not be lowercased");

        uint256 id = _payOn(SOLANA, SOL_MINT);
        vm.prank(oracle);
        sp.publishReport(id, "bafySol", keccak256("sol"), 90, 1);
        (uint256 got,,,,,) = sp.latestReport(SOLANA, SOL_MINT);
        assertEq(got, id);
        (uint256 none,,,,,) = sp.latestReport(SOLANA, lower);
        assertEq(none, 0, "different-case target is a different target");
        assertEq(sp.quote(user, SOLANA, SOL_MINT), PRICE, "re-scan multiplier 100% by default");
    }

    function test_ChainPriceOverride_Solana() public {
        vm.prank(owner);
        sp.setChainConfig(SOLANA, true, 3 * PRICE);
        assertEq(sp.quote(user, SOLANA, SOL_MINT), 3 * PRICE);
        assertEq(sp.quote(user, CHAIN, TARGET), PRICE);
    }

    function test_DisabledChainReverts() public {
        _enableAll();
        vm.prank(owner);
        sp.setChainConfig("eip155:8453", false, 0);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ScanPayments.UnsupportedChain.selector, "eip155:8453"));
        sp.requestScan("eip155:8453", TARGET);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ScanPayments.UnsupportedChain.selector, "solana:devnet"));
        sp.requestScan("solana:devnet", SOL_MINT);
    }

    function _payOn(string memory chain, string memory target) internal returns (uint256 id) {
        vm.startPrank(user);
        token.approve(address(sp), PRICE);
        id = sp.requestScan(chain, target);
        vm.stopPrank();
    }
}
