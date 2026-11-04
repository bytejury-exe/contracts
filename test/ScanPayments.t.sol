// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {BaseTest} from "./Base.t.sol";
import {ScanPayments} from "../src/ScanPayments.sol";
import {ScanRoles} from "../src/ScanRoles.sol";
import {
    MockERC20,
    MockERC20Burnable,
    FeeOnTransferToken,
    RevertingBurnToken,
    NoopBurnToken
} from "./mocks/MockTokens.sol";
import {RevertingHook, GasGuzzlerHook} from "./mocks/MockAccounts.sol";

contract ScanPaymentsTest is BaseTest {
    address internal constant DEAD = 0x000000000000000000000000000000000000dEaD;

    event UtilityTokenChanged(address indexed oldToken, address indexed newToken);
    event ScanPriceChanged(uint256 oldPrice, uint256 newPrice);
    event TreasuryChanged(address indexed oldTreasury, address indexed newTreasury);
    event BurnBpsChanged(uint16 oldBps, uint16 newBps);
    event OracleChanged(address indexed oldOracle, address indexed newOracle);
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
    event ReportPublished(
        uint256 indexed scanId,
        bytes32 indexed targetKey,
        string reportCid,
        bytes32 reportHash,
        uint8 score,
        uint8 verdict
    );
    event ExtraSplitPaid(uint256 indexed scanId, address indexed recipient, uint256 amount);
    event ReportHookFailed(uint256 indexed scanId, bytes reason);

    // ------------------------------------------------------------ constructor & defaults

    function test_Defaults() public view {
        assertEq(sp.owner(), owner);
        assertEq(sp.treasury(), treasury);
        assertEq(sp.utilityToken(), address(token));
        assertEq(sp.scanPrice(), PRICE);
        assertEq(sp.oracle(), oracle);
        assertEq(sp.burnBps(), 5000);
        assertEq(sp.nextScanId(), 1);
        assertEq(sp.creditPeriod(), 1 days);
        assertEq(uint8(sp.creditMode()), 0);
        assertTrue(sp.chainConfig(CHAIN).supported);
        (string[] memory chains,) = sp.getChains();
        assertEq(chains.length, 1);
        assertEq(chains[0], CHAIN);
    }

    function test_Constructor_ZeroChecks() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
        new ScanPayments(address(0), treasury, address(token), PRICE, oracle);
        vm.expectRevert(ScanRoles.ZeroAddress.selector);
        new ScanPayments(owner, address(0), address(token), PRICE, oracle);
        vm.expectRevert(ScanRoles.ZeroAddress.selector);
        new ScanPayments(owner, treasury, address(token), PRICE, address(0));
        vm.expectRevert(ScanPayments.InvalidAmount.selector);
        new ScanPayments(owner, treasury, address(token), 0, oracle);
    }

    function test_ZeroTokenPlaceholder_RevertsScans() public {
        ScanPayments p = new ScanPayments(owner, treasury, address(0), PRICE, oracle);
        vm.prank(user);
        vm.expectRevert(ScanPayments.TokenNotSet.selector);
        p.requestScan(CHAIN, TARGET);
        vm.prank(user);
        vm.expectRevert(ScanPayments.TokenNotSet.selector);
        p.requestScanWithPermit(CHAIN, TARGET, 0, 0, 0, 0);
    }

    // ------------------------------------------------------------ split math

    function test_RequestScan_Split5050_ViaBurn() public {
        uint256 supplyBefore = token.totalSupply();
        bytes32 key = sp.targetKey(CHAIN, TARGET);
        vm.startPrank(user);
        token.approve(address(sp), PRICE);
        vm.expectEmit(address(sp));
        emit ScanRequested(1, user, key, CHAIN, TARGET, address(token), PRICE, PRICE / 2, PRICE / 2);
        uint256 id = sp.requestScan(CHAIN, TARGET);
        vm.stopPrank();

        assertEq(id, 1);
        assertEq(sp.nextScanId(), 2);
        assertEq(sp.scanTarget(1), key);
        assertEq(token.balanceOf(treasury), PRICE / 2);
        assertEq(token.totalSupply(), supplyBefore - PRICE / 2, "burned via burn()");
        assertEq(token.balanceOf(DEAD), 0);
        assertEq(token.balanceOf(address(sp)), 0);
        assertEq(sp.totalBurned(), PRICE / 2);
        assertEq(sp.totalToTreasury(), PRICE / 2);
    }

    function test_OtherBps_AndOddAmountRounding() public {
        vm.prank(owner);
        sp.setBurnBps(3333);
        vm.prank(owner);
        sp.setScanPrice(1001);
        _pay(user);
        // burn = floor(1001 * 3333 / 10000) = 333, treasury gets the rest incl. dust
        assertEq(sp.totalBurned(), 333);
        assertEq(sp.totalToTreasury(), 668);
        assertEq(token.balanceOf(treasury), 668);
    }

    function test_BurnBps_Zero_And_Full() public {
        vm.prank(owner);
        sp.setBurnBps(0);
        _pay(user);
        assertEq(token.balanceOf(treasury), PRICE);
        assertEq(sp.totalBurned(), 0);

        vm.prank(owner);
        sp.setBurnBps(10_000);
        _pay(user, "0x2222222222222222222222222222222222222222");
        assertEq(token.balanceOf(treasury), PRICE);
        assertEq(sp.totalBurned(), PRICE);
    }

    function test_ExtraSplit() public {
        address pool = makeAddr("pool");
        vm.prank(owner);
        sp.setExtraSplit(pool, 1000);
        vm.prank(user);
        token.approve(address(sp), PRICE);
        vm.expectEmit(address(sp));
        emit ExtraSplitPaid(1, pool, PRICE / 10);
        vm.prank(user);
        sp.requestScan(CHAIN, TARGET);
        assertEq(token.balanceOf(pool), PRICE / 10);
        assertEq(token.balanceOf(treasury), PRICE * 4 / 10);
        assertEq(sp.totalToExtra(), PRICE / 10);
    }

    function test_ExtraSplit_Bounds() public {
        vm.startPrank(owner);
        vm.expectRevert(ScanPayments.InvalidBps.selector);
        sp.setExtraSplit(makeAddr("pool"), 5001);
        vm.expectRevert(ScanRoles.ZeroAddress.selector);
        sp.setExtraSplit(address(0), 1);
        sp.setExtraSplit(address(0), 0);
        sp.setExtraSplit(makeAddr("pool"), 5000);
        vm.expectRevert(ScanPayments.InvalidBps.selector);
        sp.setBurnBps(5001);
        vm.expectRevert(ScanPayments.InvalidBps.selector);
        sp.setBurnBps(10_001);
        vm.stopPrank();
    }

    function testFuzz_SplitInvariant(uint256 price, uint16 burn, uint16 extra) public {
        price = bound(price, 1, 1e30);
        burn = uint16(bound(burn, 0, 10_000));
        extra = uint16(bound(extra, 0, 10_000 - burn));
        token.mint(user, price);
        vm.startPrank(owner);
        sp.setScanPrice(price);
        sp.setBurnBps(burn);
        sp.setExtraSplit(extra == 0 ? address(0) : makeAddr("pool"), extra);
        vm.stopPrank();
        _pay(user);
        assertEq(sp.totalBurned() + sp.totalToTreasury() + sp.totalToExtra(), price);
        assertEq(token.balanceOf(address(sp)), 0);
    }

    // ------------------------------------------------------------ burn paths

    function _useToken(address t) internal {
        vm.prank(owner);
        sp.setUtilityToken(t);
    }

    function test_Burn_FallbackToDead_NoBurnFunction() public {
        MockERC20 plain = new MockERC20();
        plain.mint(user, PRICE);
        _useToken(address(plain));
        vm.startPrank(user);
        plain.approve(address(sp), PRICE);
        sp.requestScan(CHAIN, TARGET);
        vm.stopPrank();
        assertEq(plain.balanceOf(DEAD), PRICE / 2);
        assertEq(plain.balanceOf(treasury), PRICE / 2);
    }

    function test_Burn_FallbackToDead_BurnReverts() public {
        RevertingBurnToken t = new RevertingBurnToken();
        t.mint(user, PRICE);
        _useToken(address(t));
        vm.startPrank(user);
        t.approve(address(sp), PRICE);
        sp.requestScan(CHAIN, TARGET);
        vm.stopPrank();
        assertEq(t.balanceOf(DEAD), PRICE / 2);
    }

    function test_Burn_FallbackToDead_BurnIsNoop() public {
        NoopBurnToken t = new NoopBurnToken();
        t.mint(user, PRICE);
        _useToken(address(t));
        vm.startPrank(user);
        t.approve(address(sp), PRICE);
        sp.requestScan(CHAIN, TARGET);
        vm.stopPrank();
        assertEq(t.balanceOf(DEAD), PRICE / 2, "balance did not drop -> dead address");
        assertEq(t.balanceOf(address(sp)), 0);
    }

    function test_Burn_ViaBurnFunction_PlainBurnable() public {
        MockERC20Burnable b = new MockERC20Burnable();
        b.mint(user, PRICE);
        _useToken(address(b));
        vm.startPrank(user);
        b.approve(address(sp), PRICE);
        sp.requestScan(CHAIN, TARGET);
        vm.stopPrank();
        assertEq(b.totalSupply(), PRICE / 2);
        assertEq(b.balanceOf(DEAD), 0);
    }

    function test_FeeOnTransfer_UsesReceivedAmount() public {
        FeeOnTransferToken f = new FeeOnTransferToken(100); // 1%
        f.mint(user, PRICE);
        _useToken(address(f));
        uint256 received = PRICE - PRICE / 100;
        bytes32 key = sp.targetKey(CHAIN, TARGET);
        vm.startPrank(user);
        f.approve(address(sp), PRICE);
        vm.expectEmit(address(sp));
        emit ScanRequested(1, user, key, CHAIN, TARGET, address(f), received, received / 2, received - received / 2);
        sp.requestScan(CHAIN, TARGET);
        vm.stopPrank();
        assertEq(sp.totalBurned() + sp.totalToTreasury(), received);
        assertEq(f.balanceOf(address(sp)), 0);
    }

    // ------------------------------------------------------------ permit

    function _permitSig(uint256 value, uint256 deadline) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                user,
                address(sp),
                value,
                token.nonces(user),
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (v, r, s) = vm.sign(userPk, digest);
    }

    function test_RequestScanWithPermit() public {
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _permitSig(PRICE, deadline);
        vm.prank(user);
        uint256 id = sp.requestScanWithPermit(CHAIN, TARGET, deadline, v, r, s);
        assertEq(id, 1);
        assertEq(token.balanceOf(treasury), PRICE / 2);
        assertEq(token.allowance(user, address(sp)), 0);
    }

    function test_RequestScanWithPermit_FrontRunPermitStillWorks() public {
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _permitSig(PRICE, deadline);
        token.permit(user, address(sp), PRICE, deadline, v, r, s); // attacker front-runs the permit
        vm.prank(user);
        sp.requestScanWithPermit(CHAIN, TARGET, deadline, v, r, s);
        assertEq(token.balanceOf(treasury), PRICE / 2);
    }

    function test_RequestScanWithPermit_BadPermitNoAllowance_Reverts() public {
        vm.prank(user);
        vm.expectRevert();
        sp.requestScanWithPermit(CHAIN, TARGET, block.timestamp, 27, bytes32(0), bytes32(0));
    }

    // ------------------------------------------------------------ token change mid-life

    function test_TokenChange_OldTokenNoLongerAccepted() public {
        _pay(user);
        MockERC20Burnable newToken = new MockERC20Burnable();
        vm.expectEmit(address(sp));
        emit UtilityTokenChanged(address(token), address(newToken));
        _useToken(address(newToken));

        vm.startPrank(user);
        token.approve(address(sp), PRICE); // old token approval is useless now
        vm.expectRevert(); // transferFrom of new token: no balance / allowance
        sp.requestScan(CHAIN, "0x3333333333333333333333333333333333333333");
        vm.stopPrank();
        assertEq(token.allowance(user, address(sp)), PRICE, "old token untouched");

        newToken.mint(user, PRICE);
        vm.startPrank(user);
        newToken.approve(address(sp), PRICE);
        sp.requestScan(CHAIN, "0x3333333333333333333333333333333333333333");
        vm.stopPrank();
        assertEq(newToken.balanceOf(treasury), PRICE / 2);
    }

    function test_SetUtilityToken_Checks() public {
        vm.startPrank(owner);
        vm.expectRevert(ScanRoles.ZeroAddress.selector);
        sp.setUtilityToken(address(0));
        vm.expectRevert(ScanPayments.NotAContract.selector);
        sp.setUtilityToken(makeAddr("eoa"));
        vm.stopPrank();
    }

    // ------------------------------------------------------------ setters: events + access control

    function test_Setters_EmitEvents() public {
        vm.startPrank(owner);
        vm.expectEmit(address(sp));
        emit ScanPriceChanged(PRICE, 5);
        sp.setScanPrice(5);
        address t2 = makeAddr("t2");
        vm.expectEmit(address(sp));
        emit TreasuryChanged(treasury, t2);
        sp.setTreasury(t2);
        vm.expectEmit(address(sp));
        emit BurnBpsChanged(5000, 4000);
        sp.setBurnBps(4000);
        address o2 = makeAddr("o2");
        vm.expectEmit(address(sp));
        emit OracleChanged(oracle, o2);
        sp.setOracle(o2);
        vm.stopPrank();
        assertEq(sp.scanPrice(), 5);
        assertEq(sp.treasury(), t2);
        assertEq(sp.burnBps(), 4000);
        assertEq(sp.oracle(), o2);
    }

    function test_Setters_ZeroChecks() public {
        vm.startPrank(owner);
        vm.expectRevert(ScanRoles.ZeroAddress.selector);
        sp.setTreasury(address(0));
        vm.expectRevert(ScanRoles.ZeroAddress.selector);
        sp.setOracle(address(0));
        vm.expectRevert(ScanPayments.InvalidAmount.selector);
        sp.setScanPrice(0);
        vm.expectRevert(ScanRoles.ZeroAddress.selector);
        sp.setOperator(address(0), true);
        vm.expectRevert(ScanRoles.ZeroAddress.selector);
        sp.setCreditManager(address(0), true);
        vm.expectRevert(ScanRoles.ZeroAddress.selector);
        sp.setRelayer(address(0), true);
        vm.expectRevert(ScanRoles.ZeroAddress.selector);
        sp.setCreditSigner(address(0));
        vm.expectRevert(ScanRoles.ZeroAddress.selector);
        sp.rescueTokens(address(token), address(0), 1);
        vm.expectRevert(ScanPayments.NotAContract.selector);
        sp.setReportHook(makeAddr("eoa"));
        vm.stopPrank();
    }

    function test_OwnerOnlySetters_RevertForStrangerAndOperator() public {
        address op = makeAddr("op");
        vm.prank(owner);
        sp.setOperator(op, true);
        address[2] memory callers = [stranger, op];
        for (uint256 i; i < 2; ++i) {
            vm.startPrank(callers[i]);
            bytes memory err = abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, callers[i]);
            vm.expectRevert(err);
            sp.setUtilityToken(address(token));
            vm.expectRevert(err);
            sp.setTreasury(stranger);
            vm.expectRevert(err);
            sp.setBurnBps(1);
            vm.expectRevert(err);
            sp.setOracle(stranger);
            vm.expectRevert(err);
            sp.setExtraSplit(stranger, 1);
            vm.expectRevert(err);
            sp.setReportHook(address(0));
            vm.expectRevert(err);
            sp.setCreditSigner(stranger);
            vm.expectRevert(err);
            sp.setOperator(stranger, true);
            vm.expectRevert(err);
            sp.setCreditManager(stranger, true);
            vm.expectRevert(err);
            sp.unpause();
            vm.expectRevert(err);
            sp.rescueTokens(address(token), stranger, 1);
            vm.expectRevert(err);
            sp.transferOwnership(stranger);
            vm.stopPrank();
        }
    }

    function test_OracleOnly_Publish() public {
        _pay(user);
        vm.prank(stranger);
        vm.expectRevert(ScanPayments.OnlyOracle.selector);
        sp.publishReport(1, "cid", bytes32(uint256(1)), 10, 1);
        vm.prank(owner);
        vm.expectRevert(ScanPayments.OnlyOracle.selector);
        sp.publishReport(1, "cid", bytes32(uint256(1)), 10, 1);
        vm.prank(stranger);
        vm.expectRevert(ScanPayments.OnlyOracle.selector);
        sp.publishReportWithAttestation(1, "cid", bytes32(uint256(1)), 10, 1, "");
    }

    // ------------------------------------------------------------ publishing

    function test_PublishReport_StoresLatest() public {
        _pay(user);
        bytes32 key = sp.targetKey(CHAIN, TARGET);
        vm.warp(block.timestamp + 100);
        vm.expectEmit(address(sp));
        emit ReportPublished(1, key, "bafyCid", bytes32(uint256(7)), 42, 2);
        vm.prank(oracle);
        sp.publishReport(1, "bafyCid", bytes32(uint256(7)), 42, 2);
        (uint256 id, string memory cid, bytes32 h, uint8 risk, uint8 verdict, uint64 at) =
            sp.latestReport(CHAIN, TARGET);
        assertEq(id, 1);
        assertEq(cid, "bafyCid");
        assertEq(h, bytes32(uint256(7)));
        assertEq(risk, 42);
        assertEq(verdict, 2);
        assertEq(at, block.timestamp);
    }

    function test_PublishReport_Validation() public {
        _pay(user);
        vm.startPrank(oracle);
        vm.expectRevert(abi.encodeWithSelector(ScanPayments.UnknownScan.selector, 0));
        sp.publishReport(0, "c", 0, 0, 0);
        vm.expectRevert(abi.encodeWithSelector(ScanPayments.UnknownScan.selector, 2));
        sp.publishReport(2, "c", 0, 0, 0);
        vm.expectRevert(ScanPayments.InvalidVerdict.selector);
        sp.publishReport(1, "c", 0, 0, 5);
        vm.expectRevert(ScanPayments.InvalidScore.selector);
        sp.publishReport(1, "c", 0, 101, 4);
        vm.expectRevert(ScanPayments.InvalidString.selector);
        sp.publishReport(1, "", 0, 100, 4);
        sp.publishReport(1, "c", 0, 100, 4); // boundaries ok
        vm.stopPrank();
    }

    function test_PublishReport_StaleRejected_SameScanCorrectionAllowed() public {
        _pay(user);
        _pay(user, TARGET); // same target again (no cooldown by default) -> scan 2
        vm.startPrank(oracle);
        sp.publishReport(2, "new", 0, 10, 1);
        vm.expectRevert(abi.encodeWithSelector(ScanPayments.StaleReport.selector, 2));
        sp.publishReport(1, "old", 0, 90, 4);
        sp.publishReport(2, "fixed", 0, 11, 1);
        vm.stopPrank();
        (, string memory cid,,,,) = sp.latestReport(CHAIN, TARGET);
        assertEq(cid, "fixed");
    }

    function test_ReportHookFailure_DoesNotBlockPublishing() public {
        RevertingHook hook = new RevertingHook();
        vm.prank(owner);
        sp.setReportHook(address(hook));
        _pay(user);
        vm.expectEmit(address(sp));
        emit ReportHookFailed(1, abi.encodeWithSignature("Error(string)", "hook down"));
        vm.prank(oracle);
        sp.publishReport(1, "cid", 0, 10, 1);
        (uint256 id,,,,,) = sp.latestReport(CHAIN, TARGET);
        assertEq(id, 1);
        vm.prank(owner);
        sp.setReportHook(address(0));
        assertEq(sp.reportHook(), address(0));
    }

    function test_TargetKey() public view {
        assertEq(sp.targetKey(CHAIN, TARGET), keccak256(abi.encodePacked(CHAIN, ":", TARGET)));
    }

    function test_InvalidTargets() public {
        vm.startPrank(user);
        token.approve(address(sp), PRICE);
        vm.expectRevert(ScanPayments.InvalidString.selector);
        sp.requestScan(CHAIN, "");
        vm.expectRevert(ScanPayments.InvalidString.selector);
        sp.requestScan(CHAIN, string(new bytes(129)));
        vm.expectRevert(abi.encodeWithSelector(ScanPayments.UnsupportedChain.selector, "eip155:1"));
        sp.requestScan("eip155:1", TARGET);
        vm.stopPrank();
    }

    // ------------------------------------------------------------ pause

    function test_Pause_BlocksEverything_OnlyOwnerUnpauses() public {
        address op = makeAddr("op");
        vm.startPrank(owner);
        sp.setOperator(op, true);
        vm.stopPrank();
        vm.prank(stranger);
        vm.expectRevert(ScanRoles.Unauthorized.selector);
        sp.pause();
        vm.prank(op);
        sp.pause();
        assertTrue(sp.paused());

        vm.startPrank(user);
        token.approve(address(sp), PRICE);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        sp.requestScan(CHAIN, TARGET);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        sp.requestScanWithPermit(CHAIN, TARGET, 0, 0, 0, 0);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        sp.requestFreeScan(CHAIN, TARGET);
        vm.stopPrank();
        vm.prank(oracle);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        sp.publishReport(1, "c", 0, 0, 0);

        vm.prank(op);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, op));
        sp.unpause();
        vm.prank(owner);
        sp.unpause();
        _pay(user);
    }

    // ------------------------------------------------------------ ownership

    function test_Ownership_TwoStep() public {
        address newOwner = makeAddr("newOwner");
        vm.prank(owner);
        sp.transferOwnership(newOwner);
        assertEq(sp.owner(), owner);
        assertEq(sp.pendingOwner(), newOwner);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        sp.acceptOwnership();
        vm.prank(newOwner);
        sp.acceptOwnership();
        assertEq(sp.owner(), newOwner);
        assertEq(sp.pendingOwner(), address(0));
        vm.prank(owner);
        vm.expectRevert(ScanRoles.Unauthorized.selector);
        sp.setScanPrice(1);
    }

    function test_RenounceDisabled() public {
        vm.prank(owner);
        vm.expectRevert(ScanRoles.RenounceDisabled.selector);
        sp.renounceOwnership();
    }

    // ------------------------------------------------------------ rescue

    function test_RescueTokens() public {
        MockERC20 stray = new MockERC20();
        stray.mint(address(sp), 5);
        vm.prank(owner);
        sp.rescueTokens(address(stray), owner, 5);
        assertEq(stray.balanceOf(owner), 5);
    }

    function test_ReportHook_GasIsFixed() public {
        GasGuzzlerHook hook = new GasGuzzlerHook();
        vm.prank(owner);
        sp.setReportHook(address(hook));
        _pay(user);
        // too little gas to give the hook its full budget -> revert (so gas estimation always covers the hook)
        vm.prank(oracle);
        vm.expectRevert(ScanPayments.InsufficientGasForHook.selector);
        sp.publishReport{gas: 1_500_000}(1, "cid", 0, 10, 1);
        // enough gas: the hook burns exactly HOOK_GAS, fails deterministically, the report is still stored
        vm.prank(oracle);
        sp.publishReport{gas: 3_000_000}(1, "cid", 0, 10, 1);
        (uint256 id,,,,,) = sp.latestReport(CHAIN, TARGET);
        assertEq(id, 1);
    }
}
