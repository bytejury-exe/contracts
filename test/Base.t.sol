// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ScanPayments} from "../src/ScanPayments.sol";
import {HolderCredits} from "../src/HolderCredits.sol";
import {MockERC20Burnable, MockERC20Permit} from "./mocks/MockTokens.sol";

abstract contract BaseTest is Test {
    string internal constant CHAIN = "eip155:4663";
    string internal constant TARGET = "0x1111111111111111111111111111111111111111";
    uint256 internal constant PRICE = 100e18;

    address internal owner = makeAddr("owner");
    address internal treasury = makeAddr("treasury");
    address internal oracle;
    uint256 internal oraclePk;
    address internal user;
    uint256 internal userPk;
    address internal stranger = makeAddr("stranger");
    address internal relayer = makeAddr("relayer");

    ScanPayments internal sp;
    MockERC20Permit internal token;

    function setUp() public virtual {
        vm.chainId(4663);
        vm.warp(1_800_000_000);
        (oracle, oraclePk) = makeAddrAndKey("oracle");
        (user, userPk) = makeAddrAndKey("user");
        token = new MockERC20Permit();
        sp = new ScanPayments(owner, treasury, address(token), PRICE, oracle);
        token.mint(user, 1_000_000e18);
    }

    // ------------------------------------------------------------ helpers

    function _pay(address payer) internal returns (uint256 scanId) {
        return _pay(payer, TARGET);
    }

    function _pay(address payer, string memory target) internal returns (uint256 scanId) {
        uint256 price = sp.quote(payer, CHAIN, target);
        vm.startPrank(payer);
        token.approve(address(sp), price);
        scanId = sp.requestScan(CHAIN, target);
        vm.stopPrank();
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _setTiers(uint256 min1, uint32 free1, uint16 disc1, uint256 min2, uint32 free2, uint16 disc2) internal {
        HolderCredits.Tier[] memory tiers = new HolderCredits.Tier[](2);
        tiers[0] = HolderCredits.Tier(min1, free1, disc1);
        tiers[1] = HolderCredits.Tier(min2, free2, disc2);
        vm.prank(owner);
        sp.setTiers(tiers);
    }

    function _setMode(HolderCredits.CreditMode mode) internal {
        vm.prank(owner);
        sp.setCreditConfig(mode, 1 days, 3 days, true);
    }
}
