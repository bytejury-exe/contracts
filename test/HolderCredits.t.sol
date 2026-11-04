// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseTest} from "./Base.t.sol";
import {ScanPayments} from "../src/ScanPayments.sol";
import {HolderCredits} from "../src/HolderCredits.sol";
import {ScanRoles} from "../src/ScanRoles.sol";
import {MockERC1271Wallet} from "./mocks/MockAccounts.sol";

contract HolderCreditsTest is BaseTest {
    address internal holder = makeAddr("holder");
    address internal signer;
    uint256 internal signerPk;
    address internal op = makeAddr("operator");
    address internal cm = makeAddr("creditManager");

    event FreeScanUsed(
        uint256 indexed scanId, address indexed holder, HolderCredits.CreditSource source, uint256 tierId
    );
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

    function setUp() public override {
        super.setUp();
        (signer, signerPk) = makeAddrAndKey("creditSigner");
        vm.startPrank(owner);
        sp.setOperator(op, true);
        sp.setCreditManager(cm, true);
        sp.setCreditSigner(signer);
        vm.stopPrank();
        // tier1: >= 1000 tokens, 1 free/day, 0% off; tier2: >= 10000 tokens, 2 free/day, 20% off
        _setTiers(1000e18, 1, 0, 10_000e18, 2, 2000);
    }

    function _t(uint256 i) internal pure returns (string memory) {
        return string.concat("0x", vm.toString(bytes32(i)));
    }

    function _free(address who, string memory target) internal returns (uint256) {
        vm.prank(who);
        return sp.requestFreeScan(CHAIN, target);
    }

    // ------------------------------------------------------------ tiers

    function test_SetTiers_Validation() public {
        HolderCredits.Tier[] memory t = new HolderCredits.Tier[](2);
        t[0] = HolderCredits.Tier(10, 1, 0);
        t[1] = HolderCredits.Tier(10, 1, 0); // not strictly increasing
        vm.startPrank(op);
        vm.expectRevert(HolderCredits.InvalidTiers.selector);
        sp.setTiers(t);
        t[1] = HolderCredits.Tier(11, 1, 10_001); // discount too high
        vm.expectRevert(HolderCredits.InvalidTiers.selector);
        sp.setTiers(t);
        t[0] = HolderCredits.Tier(0, 1, 0); // zero min balance
        t[1] = HolderCredits.Tier(11, 1, 0);
        vm.expectRevert(HolderCredits.InvalidTiers.selector);
        sp.setTiers(t);
        vm.expectRevert(HolderCredits.InvalidTiers.selector);
        sp.setTiers(new HolderCredits.Tier[](11));
        vm.stopPrank();
        vm.prank(stranger);
        vm.expectRevert(ScanRoles.Unauthorized.selector);
        sp.setTiers(t);
    }

    function test_SetTiers_ReplaceAndRemove() public {
        assertEq(sp.getTiers().length, 2);
        vm.prank(op);
        sp.setTiers(new HolderCredits.Tier[](0));
        assertEq(sp.getTiers().length, 0);
        assertEq(sp.tierOf(user), 0);
    }

    function test_TierOf_Boundaries() public {
        token.mint(holder, 1000e18 - 1);
        assertEq(sp.tierOf(holder), 0);
        token.mint(holder, 1);
        assertEq(sp.tierOf(holder), 1);
        token.mint(holder, 9000e18 - 1);
        assertEq(sp.tierOf(holder), 1);
        token.mint(holder, 1);
        assertEq(sp.tierOf(holder), 2);
    }

    function test_CreditConfig_Validation() public {
        vm.startPrank(op);
        vm.expectRevert(HolderCredits.InvalidCreditConfig.selector);
        sp.setCreditConfig(HolderCredits.CreditMode.ON_CHAIN_BALANCE, 1 hours - 1, 0, true);
        vm.expectRevert(HolderCredits.InvalidCreditConfig.selector);
        sp.setCreditConfig(HolderCredits.CreditMode.ON_CHAIN_BALANCE, 365 days + 1, 0, true);
        vm.expectRevert(HolderCredits.InvalidCreditConfig.selector);
        sp.setCreditConfig(HolderCredits.CreditMode.ON_CHAIN_BALANCE, 1 days, 365 days + 1, true);
        sp.setTiers(new HolderCredits.Tier[](0));
        vm.expectRevert(HolderCredits.InvalidCreditConfig.selector);
        sp.setCreditConfig(HolderCredits.CreditMode.ON_CHAIN_BALANCE, 1 days, 0, true);
        sp.setCreditConfig(HolderCredits.CreditMode.OFF, 1 days, 0, true); // OFF without tiers is fine
        vm.stopPrank();
        vm.prank(stranger);
        vm.expectRevert(ScanRoles.Unauthorized.selector);
        sp.setCreditConfig(HolderCredits.CreditMode.OFF, 1 days, 0, true);
    }

    // ------------------------------------------------------------ ON_CHAIN_BALANCE

    function test_ModeOff_NoTierCredits() public {
        token.mint(holder, 10_000e18);
        assertEq(sp.freeScansLeft(holder), 0);
        vm.prank(holder);
        vm.expectRevert(HolderCredits.NoFreeScansLeft.selector);
        sp.requestFreeScan(CHAIN, TARGET);
        assertEq(sp.quote(holder, CHAIN, TARGET), PRICE, "no discount when OFF");
    }

    function test_BalanceMode_FreeScanAndEvents() public {
        _setMode(HolderCredits.CreditMode.ON_CHAIN_BALANCE);
        token.mint(holder, 1000e18);
        assertEq(sp.freeScansLeft(holder), 1);
        bytes32 key = sp.targetKey(CHAIN, TARGET);
        vm.expectEmit(address(sp));
        emit ScanRequested(1, holder, key, CHAIN, TARGET, address(token), 0, 0, 0);
        vm.expectEmit(address(sp));
        emit FreeScanUsed(1, holder, HolderCredits.CreditSource.TIER, 1);
        _free(holder, TARGET);
        assertEq(sp.freeScansLeft(holder), 0);
        assertEq(token.balanceOf(holder), 1000e18, "nothing charged");
        vm.prank(holder);
        vm.expectRevert(HolderCredits.NoFreeScansLeft.selector);
        sp.requestFreeScan(CHAIN, _t(2));
    }

    function test_BalanceMode_DailyResetAcrossDayBoundary() public {
        _setMode(HolderCredits.CreditMode.ON_CHAIN_BALANCE);
        token.mint(holder, 10_000e18); // tier2 = 2/day
        // move to 1 second before a UTC day boundary
        uint256 nextDay = (block.timestamp / 1 days + 1) * 1 days;
        vm.warp(nextDay - 1);
        _free(holder, _t(1));
        _free(holder, _t(2));
        vm.prank(holder);
        vm.expectRevert(HolderCredits.NoFreeScansLeft.selector);
        sp.requestFreeScan(CHAIN, _t(3));
        vm.warp(nextDay); // epoch-aligned: new bucket starts exactly at 00:00 UTC
        assertEq(sp.currentPeriod(), nextDay / 1 days);
        assertEq(sp.freeScansLeft(holder), 2);
        _free(holder, _t(3));
        (uint64 periodIndex, uint32 used) = sp.usage(holder);
        assertEq(periodIndex, nextDay / 1 days);
        assertEq(used, 1);
    }

    function test_BalanceMode_DroppingBelowThresholdLosesTier() public {
        _setMode(HolderCredits.CreditMode.ON_CHAIN_BALANCE);
        token.mint(holder, 1000e18);
        vm.prank(holder);
        token.transfer(stranger, 1);
        vm.prank(holder);
        vm.expectRevert(HolderCredits.NoFreeScansLeft.selector);
        sp.requestFreeScan(CHAIN, TARGET);
    }

    function test_TierDiscount_OnPaidScans() public {
        _setMode(HolderCredits.CreditMode.ON_CHAIN_BALANCE);
        assertEq(sp.quote(user, CHAIN, TARGET), PRICE * 80 / 100, "user holds 1M -> tier2 20% off");
        _pay(user);
        assertEq(sp.totalBurned() + sp.totalToTreasury(), PRICE * 80 / 100);
    }

    function test_FullDiscount_ZeroPriceScan() public {
        HolderCredits.Tier[] memory t = new HolderCredits.Tier[](1);
        t[0] = HolderCredits.Tier(1, 0, 10_000);
        vm.prank(op);
        sp.setTiers(t);
        _setMode(HolderCredits.CreditMode.ON_CHAIN_BALANCE);
        uint256 balanceBefore = token.balanceOf(user);
        vm.prank(user);
        sp.requestScan(CHAIN, TARGET);
        assertEq(token.balanceOf(user), balanceBefore);
        assertEq(sp.totalBurned(), 0);
    }

    // ------------------------------------------------------------ manual credits

    function test_ManualCredits_GrantRevokeAndOrder() public {
        address[] memory who = new address[](1);
        who[0] = holder;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 2;
        vm.prank(stranger);
        vm.expectRevert(ScanRoles.Unauthorized.selector);
        sp.grantCredits(who, amounts);
        vm.prank(cm);
        sp.grantCredits(who, amounts);
        assertEq(sp.manualCredits(holder), 2);

        // Manual credits work even with credit mode OFF
        vm.expectEmit(address(sp));
        emit FreeScanUsed(1, holder, HolderCredits.CreditSource.MANUAL, 0);
        _free(holder, _t(1));
        assertEq(sp.manualCredits(holder), 1);

        // manual first (default) with tier available -> manual consumed
        _setMode(HolderCredits.CreditMode.ON_CHAIN_BALANCE);
        token.mint(holder, 1000e18);
        _free(holder, _t(2));
        assertEq(sp.manualCredits(holder), 0);
        assertEq(sp.freeScansLeft(holder), 1);

        // tier first: tier consumed, then manual as fallback
        vm.prank(cm);
        sp.grantCredits(who, amounts);
        vm.prank(op);
        sp.setCreditConfig(HolderCredits.CreditMode.ON_CHAIN_BALANCE, 1 days, 0, false);
        vm.expectEmit(address(sp));
        emit FreeScanUsed(3, holder, HolderCredits.CreditSource.TIER, 1);
        _free(holder, _t(3));
        assertEq(sp.manualCredits(holder), 2);
        vm.expectEmit(address(sp));
        emit FreeScanUsed(4, holder, HolderCredits.CreditSource.MANUAL, 0);
        _free(holder, _t(4));
        assertEq(sp.manualCredits(holder), 1);

        // revoke clamps at zero
        amounts[0] = 5;
        vm.prank(cm);
        sp.revokeCredits(who, amounts);
        assertEq(sp.manualCredits(holder), 0);
    }

    function test_ManualCredits_Validation() public {
        address[] memory who = new address[](1);
        uint256[] memory amounts = new uint256[](2);
        vm.startPrank(owner);
        vm.expectRevert(HolderCredits.LengthMismatch.selector);
        sp.grantCredits(who, amounts);
        vm.expectRevert(HolderCredits.LengthMismatch.selector);
        sp.revokeCredits(who, amounts);
        amounts = new uint256[](1);
        vm.expectRevert(ScanRoles.ZeroAddress.selector);
        sp.grantCredits(who, amounts);
        vm.stopPrank();
        vm.prank(stranger);
        vm.expectRevert(ScanRoles.Unauthorized.selector);
        sp.revokeCredits(who, amounts);
    }

    // ------------------------------------------------------------ vouchers

    function _voucher(address h, string memory target, uint256 tierId, uint256 nonce, uint256 deadline)
        internal
        pure
        returns (HolderCredits.FreeScanVoucher memory)
    {
        return HolderCredits.FreeScanVoucher(h, CHAIN, target, tierId, nonce, deadline);
    }

    function _voucherDigest(HolderCredits.FreeScanVoucher memory v) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                sp.FREE_SCAN_VOUCHER_TYPEHASH(),
                v.holder,
                keccak256(bytes(v.chain)),
                keccak256(bytes(v.target)),
                v.tierId,
                v.nonce,
                v.deadline
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", sp.DOMAIN_SEPARATOR(), structHash));
    }

    function test_Voucher_DigestMatchesIndependentEip712() public view {
        HolderCredits.FreeScanVoucher memory v = _voucher(holder, TARGET, 1, 7, 2_000_000_000);
        string memory json = string.concat(
            '{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},',
            '{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],',
            '"FreeScanVoucher":[{"name":"holder","type":"address"},{"name":"chain","type":"string"},',
            '{"name":"target","type":"string"},{"name":"tierId","type":"uint256"},{"name":"nonce","type":"uint256"},',
            '{"name":"deadline","type":"uint256"}]},"primaryType":"FreeScanVoucher",',
            '"domain":{"name":"ScanPayments","version":"1","chainId":4663,"verifyingContract":"',
            vm.toString(address(sp)),
            '"},"message":{"holder":"',
            vm.toString(holder),
            '","chain":"eip155:4663","target":"',
            TARGET,
            '","tierId":1,"nonce":7,"deadline":2000000000}}'
        );
        assertEq(vm.eip712HashTypedData(json), _voucherDigest(v));
    }

    function test_Voucher_HappyPath_ReplayAndRelayer() public {
        _setMode(HolderCredits.CreditMode.SIGNED_VOUCHER);
        HolderCredits.FreeScanVoucher memory v = _voucher(holder, TARGET, 2, 1, block.timestamp + 1 hours);
        bytes memory sig = _sign(signerPk, _voucherDigest(v));

        // relayer submits gaslessly on behalf of holder (holder owns 0 tokens: balance not checked in this mode)
        vm.expectEmit(address(sp));
        emit FreeScanUsed(1, holder, HolderCredits.CreditSource.VOUCHER, 2);
        vm.prank(relayer);
        sp.requestFreeScanWithVoucher(v, sig);
        assertTrue(sp.voucherNonceUsed(holder, 1));

        vm.prank(holder);
        vm.expectRevert(HolderCredits.VoucherNonceUsed.selector);
        sp.requestFreeScanWithVoucher(v, sig);
    }

    function test_Voucher_Rejections() public {
        HolderCredits.FreeScanVoucher memory v = _voucher(holder, TARGET, 1, 1, block.timestamp + 1 hours);
        bytes memory sig = _sign(signerPk, _voucherDigest(v));
        vm.startPrank(holder);
        // mode OFF / ON_CHAIN_BALANCE
        vm.expectRevert(HolderCredits.VoucherModeDisabled.selector);
        sp.requestFreeScanWithVoucher(v, sig);
        vm.stopPrank();
        _setMode(HolderCredits.CreditMode.SIGNED_VOUCHER);
        vm.startPrank(holder);
        // wrong signer
        bytes memory wrongSig = _sign(userPk, _voucherDigest(v));
        vm.expectRevert(HolderCredits.InvalidSignature.selector);
        sp.requestFreeScanWithVoucher(v, wrongSig);
        // tampered field
        HolderCredits.FreeScanVoucher memory tampered = _voucher(holder, _t(9), 1, 1, v.deadline);
        vm.expectRevert(HolderCredits.InvalidSignature.selector);
        sp.requestFreeScanWithVoucher(tampered, sig);
        // invalid tier
        HolderCredits.FreeScanVoucher memory badTier = _voucher(holder, TARGET, 3, 1, v.deadline);
        bytes memory badTierSig = _sign(signerPk, _voucherDigest(badTier));
        vm.expectRevert(abi.encodeWithSelector(HolderCredits.InvalidTier.selector, 3));
        sp.requestFreeScanWithVoucher(badTier, badTierSig);
        HolderCredits.FreeScanVoucher memory tier0 = _voucher(holder, TARGET, 0, 1, v.deadline);
        bytes memory tier0Sig = _sign(signerPk, _voucherDigest(tier0));
        vm.expectRevert(abi.encodeWithSelector(HolderCredits.InvalidTier.selector, 0));
        sp.requestFreeScanWithVoucher(tier0, tier0Sig);
        vm.stopPrank();
        // expired
        vm.warp(v.deadline + 1);
        vm.prank(holder);
        vm.expectRevert(HolderCredits.VoucherExpired.selector);
        sp.requestFreeScanWithVoucher(v, sig);
    }

    function test_Voucher_PerPeriodCapEnforced() public {
        _setMode(HolderCredits.CreditMode.SIGNED_VOUCHER);
        HolderCredits.FreeScanVoucher memory v1 = _voucher(holder, _t(1), 1, 1, block.timestamp + 1 hours);
        HolderCredits.FreeScanVoucher memory v2 = _voucher(holder, _t(2), 1, 2, block.timestamp + 1 hours);
        v2.deadline = block.timestamp + 2 days;
        bytes memory sig1 = _sign(signerPk, _voucherDigest(v1));
        bytes memory sig2 = _sign(signerPk, _voucherDigest(v2));
        vm.startPrank(holder);
        sp.requestFreeScanWithVoucher(v1, sig1);
        vm.expectRevert(HolderCredits.NoFreeScansLeft.selector);
        sp.requestFreeScanWithVoucher(v2, sig2);
        vm.stopPrank();
        vm.warp(block.timestamp + 1 days);
        vm.prank(holder);
        sp.requestFreeScanWithVoucher(v2, sig2);
    }

    function test_Voucher_BalanceAndVoucherMode() public {
        _setMode(HolderCredits.CreditMode.BALANCE_AND_VOUCHER);
        HolderCredits.FreeScanVoucher memory v = _voucher(holder, TARGET, 1, 1, block.timestamp + 1 hours);
        bytes memory sig = _sign(signerPk, _voucherDigest(v));
        vm.prank(holder);
        vm.expectRevert(HolderCredits.BalanceTooLow.selector);
        sp.requestFreeScanWithVoucher(v, sig);
        token.mint(holder, 1000e18);
        vm.prank(holder);
        sp.requestFreeScanWithVoucher(v, sig);
        // plain requestFreeScan without voucher gives no tier credit in voucher modes
        vm.prank(holder);
        vm.expectRevert(HolderCredits.NoFreeScansLeft.selector);
        sp.requestFreeScan(CHAIN, _t(5));
    }

    function test_Voucher_BalanceAndVoucher_TokenUnset() public {
        ScanPayments p = new ScanPayments(owner, treasury, address(0), PRICE, oracle);
        HolderCredits.Tier[] memory t = new HolderCredits.Tier[](1);
        t[0] = HolderCredits.Tier(1, 1, 0);
        vm.startPrank(owner);
        p.setTiers(t);
        p.setCreditSigner(signer);
        p.setCreditConfig(HolderCredits.CreditMode.BALANCE_AND_VOUCHER, 1 days, 0, true);
        vm.stopPrank();
        HolderCredits.FreeScanVoucher memory v = _voucher(holder, TARGET, 1, 1, block.timestamp + 1 hours);
        bytes32 structHash = keccak256(
            abi.encode(
                p.FREE_SCAN_VOUCHER_TYPEHASH(),
                holder,
                keccak256(bytes(CHAIN)),
                keccak256(bytes(TARGET)),
                1,
                1,
                v.deadline
            )
        );
        bytes memory sig = _sign(signerPk, keccak256(abi.encodePacked("\x19\x01", p.DOMAIN_SEPARATOR(), structHash)));
        vm.prank(holder);
        vm.expectRevert(HolderCredits.BalanceTooLow.selector);
        p.requestFreeScanWithVoucher(v, sig);
    }

    function test_Voucher_Erc1271CreditSigner() public {
        MockERC1271Wallet wallet = new MockERC1271Wallet(signer);
        vm.prank(owner);
        sp.setCreditSigner(address(wallet));
        _setMode(HolderCredits.CreditMode.SIGNED_VOUCHER);
        HolderCredits.FreeScanVoucher memory v = _voucher(holder, TARGET, 1, 1, block.timestamp + 1 hours);
        bytes memory sig = _sign(signerPk, _voucherDigest(v));
        vm.prank(holder);
        sp.requestFreeScanWithVoucher(v, sig);
    }

    function test_Voucher_RelayerAllowlistAndBySigPause() public {
        _setMode(HolderCredits.CreditMode.SIGNED_VOUCHER);
        HolderCredits.FreeScanVoucher memory v = _voucher(holder, TARGET, 1, 1, block.timestamp + 1 hours);
        bytes memory sig = _sign(signerPk, _voucherDigest(v));
        vm.startPrank(op);
        sp.setRelayerAllowlistEnabled(true);
        vm.stopPrank();
        vm.prank(stranger);
        vm.expectRevert(ScanPayments.RelayerNotAllowed.selector);
        sp.requestFreeScanWithVoucher(v, sig);

        uint8 bySig = sp.FEATURE_BY_SIG();
        vm.prank(op);
        sp.setPausedFeatures(bySig);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ScanPayments.FeaturePaused.selector, 4));
        sp.requestFreeScanWithVoucher(v, sig);

        vm.prank(op);
        sp.setPausedFeatures(0);
        vm.prank(op);
        sp.setRelayer(relayer, true);
        vm.prank(relayer);
        sp.requestFreeScanWithVoucher(v, sig);
    }

    // ------------------------------------------------------------ prices, chains, re-scan, feature flags

    function test_ChainPriceOverride_AndSupportedChains() public {
        vm.prank(op);
        sp.setChainConfig("solana:mainnet", true, 300e18);
        assertEq(sp.quote(user, "solana:mainnet", "So1anaMint111"), 300e18);
        assertEq(sp.quote(user, CHAIN, TARGET), PRICE);
        vm.startPrank(user);
        token.approve(address(sp), 300e18);
        sp.requestScan("solana:mainnet", "So1anaMint111");
        vm.stopPrank();
        assertEq(sp.totalBurned() + sp.totalToTreasury(), 300e18);

        vm.prank(op);
        sp.setChainConfig("solana:mainnet", false, 300e18);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ScanPayments.UnsupportedChain.selector, "solana:mainnet"));
        sp.requestScan("solana:mainnet", "Other");
        (string[] memory chains, ScanPayments.ChainConfig[] memory cfgs) = sp.getChains();
        assertEq(chains.length, 2, "re-configuring does not duplicate");
        assertFalse(cfgs[1].supported);

        vm.startPrank(op);
        vm.expectRevert(ScanPayments.InvalidString.selector);
        sp.setChainConfig("", true, 0);
        vm.stopPrank();
        vm.prank(stranger);
        vm.expectRevert(ScanRoles.Unauthorized.selector);
        sp.setChainConfig("x", true, 0);
    }

    function test_RescanPriceAndCooldown() public {
        vm.prank(op);
        sp.setRescanPolicy(5000, 1 hours);
        _pay(user);
        vm.prank(oracle);
        sp.publishReport(1, "cid", 0, 1, 1);
        assertEq(sp.quote(user, CHAIN, TARGET), PRICE / 2, "re-scan at 50%");

        vm.startPrank(user);
        token.approve(address(sp), PRICE);
        uint256 availableAt = block.timestamp + 1 hours;
        vm.expectRevert(abi.encodeWithSelector(ScanPayments.RescanCooldownActive.selector, availableAt));
        sp.requestScan(CHAIN, TARGET);
        vm.warp(availableAt);
        sp.requestScan(CHAIN, TARGET);
        vm.stopPrank();
        assertEq(sp.totalBurned() + sp.totalToTreasury(), PRICE + PRICE / 2);

        vm.startPrank(op);
        vm.expectRevert(ScanPayments.InvalidBps.selector);
        sp.setRescanPolicy(0, 0);
        vm.expectRevert(ScanPayments.InvalidBps.selector);
        sp.setRescanPolicy(30_001, 0);
        vm.expectRevert(ScanPayments.InvalidBps.selector);
        sp.setRescanPolicy(10_000, 30 days + 1);
        vm.stopPrank();
    }

    function test_FeatureFlags() public {
        uint8 mask = sp.FEATURE_PAID_SCANS() | sp.FEATURE_FREE_SCANS() | sp.FEATURE_PUBLISHING();
        vm.prank(op);
        sp.setPausedFeatures(mask);
        vm.startPrank(user);
        token.approve(address(sp), PRICE);
        vm.expectRevert(abi.encodeWithSelector(ScanPayments.FeaturePaused.selector, 1));
        sp.requestScan(CHAIN, TARGET);
        vm.expectRevert(abi.encodeWithSelector(ScanPayments.FeaturePaused.selector, 2));
        sp.requestFreeScan(CHAIN, TARGET);
        vm.stopPrank();
        vm.prank(oracle);
        vm.expectRevert(abi.encodeWithSelector(ScanPayments.FeaturePaused.selector, 8));
        sp.publishReport(1, "c", 0, 0, 0);
        vm.prank(stranger);
        vm.expectRevert(ScanRoles.Unauthorized.selector);
        sp.setPausedFeatures(0);
        vm.prank(op);
        sp.setPausedFeatures(0);
        _pay(user);
    }

    function test_OperatorPermissions() public {
        vm.startPrank(op);
        sp.setScanPrice(1);
        sp.setRescanPolicy(10_000, 0);
        sp.setChainConfig("eip155:8453", true, 0);
        sp.setRelayerAllowlistEnabled(true);
        sp.setRelayer(relayer, true);
        sp.setCreditConfig(HolderCredits.CreditMode.ON_CHAIN_BALANCE, 2 days, 1 days, false);
        vm.stopPrank();
        vm.prank(owner);
        sp.setOperator(op, false);
        vm.prank(op);
        vm.expectRevert(ScanRoles.Unauthorized.selector);
        sp.setScanPrice(2);
        vm.prank(stranger);
        vm.expectRevert(ScanRoles.Unauthorized.selector);
        sp.setRelayer(relayer, false);
        vm.prank(stranger);
        vm.expectRevert(ScanRoles.Unauthorized.selector);
        sp.setRelayerAllowlistEnabled(false);
        vm.prank(stranger);
        vm.expectRevert(ScanRoles.Unauthorized.selector);
        sp.setRescanPolicy(1, 0);
    }

    function test_GetConfig() public {
        vm.startPrank(owner);
        sp.setExtraSplit(makeAddr("pool"), 100);
        sp.setRescanPolicy(7000, 60);
        sp.setPausedFeatures(2);
        sp.setRelayerAllowlistEnabled(true);
        sp.setCreditConfig(HolderCredits.CreditMode.SIGNED_VOUCHER, 1 days, 3 days, false);
        vm.stopPrank();
        ScanPayments.Config memory c = sp.getConfig();
        assertEq(c.utilityToken, address(token));
        assertEq(c.treasury, treasury);
        assertEq(c.oracle, oracle);
        assertEq(c.creditSigner, signer);
        assertEq(c.extraRecipient, makeAddr("pool"));
        assertEq(c.reportHook, address(0));
        assertEq(c.scanPrice, PRICE);
        assertEq(c.burnBps, 5000);
        assertEq(c.extraBps, 100);
        assertEq(c.rescanPriceBps, 7000);
        assertEq(c.rescanCooldown, 60);
        assertEq(uint8(c.creditMode), 2);
        assertEq(c.creditPeriod, 1 days);
        assertEq(c.minHoldSeconds, 3 days);
        assertFalse(c.manualCreditsFirst);
        assertEq(c.pausedFeatures, 2);
        assertFalse(c.paused);
        assertTrue(c.relayerAllowlistEnabled);
        assertEq(c.nextScanId, 1);
    }

    function test_PartialRevoke_AndNoTierNoDiscount() public {
        address[] memory who = new address[](1);
        who[0] = holder;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 3;
        vm.prank(cm);
        sp.grantCredits(who, amounts);
        amounts[0] = 1;
        vm.prank(cm);
        sp.revokeCredits(who, amounts);
        assertEq(sp.manualCredits(holder), 2);
        _setMode(HolderCredits.CreditMode.ON_CHAIN_BALANCE);
        assertEq(sp.quote(holder, CHAIN, TARGET), PRICE, "holder without tokens gets no discount");
    }
}
