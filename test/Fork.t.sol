// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ScanPayments} from "../src/ScanPayments.sol";

/// @notice Fork tests against Robinhood Chain mainnet with the real TACITA test utility token.
///         Skipped unless ROBINHOOD_RPC_URL is set, e.g.
///         ROBINHOOD_RPC_URL=https://rpc.mainnet.chain.robinhood.com forge test --match-contract ForkTest
contract ForkTest is Test {
    IERC20 internal constant TACITA = IERC20(0xaA7cD9515dF27f8947ACe7c3eafe5a441818e828);
    address internal constant DEAD = 0x000000000000000000000000000000000000dEaD;
    uint256 internal constant PRICE = 1000e18;

    ScanPayments internal sp;
    address internal treasury = makeAddr("treasury");
    address internal user = makeAddr("user");
    bool internal noFork;

    function setUp() public {
        string memory rpc = vm.envOr("ROBINHOOD_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            noFork = true;
            return;
        }
        vm.createSelectFork(rpc);
        assertEq(block.chainid, 4663);
        sp = new ScanPayments(makeAddr("owner"), treasury, address(TACITA), PRICE, makeAddr("oracle"));
        deal(address(TACITA), user, 10 * PRICE);
    }

    function test_Fork_BurnReducesTotalSupply_AndTreasurySplit() public {
        vm.skip(noFork);
        uint256 supplyBefore = TACITA.totalSupply();
        uint256 deadBefore = TACITA.balanceOf(DEAD);
        vm.startPrank(user);
        TACITA.approve(address(sp), PRICE);
        sp.requestScan("eip155:4663", "0xaa7cd9515df27f8947ace7c3eafe5a441818e828");
        vm.stopPrank();
        assertEq(TACITA.totalSupply(), supplyBefore - PRICE / 2, "burn() path burned real supply");
        assertEq(TACITA.balanceOf(DEAD), deadBefore, "no dead-address fallback needed");
        assertEq(TACITA.balanceOf(treasury), PRICE / 2);
        assertEq(TACITA.balanceOf(address(sp)), 0);
    }

    function test_Fork_PermitPath_NonPermitToken() public {
        vm.skip(noFork);
        // TACITA has no permit(): the try/catch swallows the failure ...
        vm.prank(user);
        vm.expectRevert(); // ... and without an allowance transferFrom fails
        sp.requestScanWithPermit("eip155:4663", "0x01", block.timestamp, 27, bytes32(0), bytes32(0));

        // ... while an existing allowance lets the same call go through.
        vm.startPrank(user);
        TACITA.approve(address(sp), PRICE);
        sp.requestScanWithPermit("eip155:4663", "0x01", block.timestamp, 27, bytes32(0), bytes32(0));
        vm.stopPrank();
        assertEq(TACITA.balanceOf(treasury), PRICE / 2);
    }
}
