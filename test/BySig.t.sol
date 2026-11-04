// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {BaseTest} from "./Base.t.sol";
import {ScanPayments} from "../src/ScanPayments.sol";
import {HolderCredits} from "../src/HolderCredits.sol";
import {MockERC1271Wallet} from "./mocks/MockAccounts.sol";

contract BySigTest is BaseTest {
    ScanPayments.PermitSig internal noPermit;

    // ------------------------------------------------------------ helpers

    function _req(address payer, uint256 maxPrice, uint256 nonce, uint256 deadline)
        internal
        pure
        returns (ScanPayments.ScanRequest memory)
    {
        return ScanPayments.ScanRequest(payer, CHAIN, TARGET, maxPrice, nonce, deadline);
    }

    function _reqDigest(ScanPayments.ScanRequest memory r) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                sp.SCAN_REQUEST_TYPEHASH(),
                r.payer,
                keccak256(bytes(r.chain)),
                keccak256(bytes(r.target)),
                r.maxPrice,
                r.nonce,
                r.deadline
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", sp.DOMAIN_SEPARATOR(), structHash));
    }

    function _report(uint256 scanId, uint256 deadline) internal pure returns (ScanPayments.PublishReport memory) {
        return ScanPayments.PublishReport(scanId, "bafyReport", keccak256("report"), 30, 2, "", deadline);
    }

    function _reportDigest(ScanPayments.PublishReport memory p) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                sp.PUBLISH_REPORT_TYPEHASH(),
                p.scanId,
                keccak256(bytes(p.reportCid)),
                p.reportHash,
                p.score,
                p.verdict,
                keccak256(p.attestation),
                p.deadline
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", sp.DOMAIN_SEPARATOR(), structHash));
    }

    function _permit(address owner_, uint256 pk, uint256 value, uint256 deadline)
        internal
        view
        returns (ScanPayments.PermitSig memory p)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                owner_,
                address(sp),
                value,
                token.nonces(owner_),
                deadline
            )
        );
        (p.v, p.r, p.s) = vm.sign(pk, keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash)));
        p.deadline = deadline;
    }

    // ------------------------------------------------------------ domain

    function test_Domain_Erc5267() public view {
        (bytes1 fields, string memory name, string memory version, uint256 chainId, address verifying,,) =
            sp.eip712Domain();
        assertEq(fields, hex"0f");
        assertEq(name, "ScanPayments");
        assertEq(version, "1");
        assertEq(chainId, 4663);
        assertEq(verifying, address(sp));
        assertEq(
            sp.DOMAIN_SEPARATOR(),
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    keccak256("ScanPayments"),
                    keccak256("1"),
                    uint256(4663),
                    address(sp)
                )
            )
        );
    }

    function test_ScanRequestDigest_MatchesIndependentEip712() public view {
        ScanPayments.ScanRequest memory r = _req(user, PRICE, 0, 2_000_000_000);
        string memory json = string.concat(
            '{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},',
            '{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],',
            '"ScanRequest":[{"name":"payer","type":"address"},{"name":"chain","type":"string"},',
            '{"name":"target","type":"string"},{"name":"maxPrice","type":"uint256"},{"name":"nonce","type":"uint256"},',
            '{"name":"deadline","type":"uint256"}]},"primaryType":"ScanRequest",',
            '"domain":{"name":"ScanPayments","version":"1","chainId":4663,"verifyingContract":"',
            vm.toString(address(sp)),
            '"},"message":{"payer":"',
            vm.toString(user),
            '","chain":"eip155:4663","target":"',
            TARGET,
            '","maxPrice":"100000000000000000000","nonce":0,"deadline":2000000000}}'
        );
        assertEq(vm.eip712HashTypedData(json), _reqDigest(r));
    }

    function test_PublishReportDigest_MatchesIndependentEip712() public view {
        ScanPayments.PublishReport memory p = _report(1, 2_000_000_000);
        p.attestation = hex"c0ffee";
        string memory json = string.concat(
            '{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},',
            '{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],',
            '"PublishReport":[{"name":"scanId","type":"uint256"},{"name":"reportCid","type":"string"},',
            '{"name":"reportHash","type":"bytes32"},{"name":"score","type":"uint8"},{"name":"verdict","type":"uint8"},',
            '{"name":"attestation","type":"bytes"},{"name":"deadline","type":"uint256"}]},"primaryType":"PublishReport",',
            '"domain":{"name":"ScanPayments","version":"1","chainId":4663,"verifyingContract":"',
            vm.toString(address(sp)),
            '"},"message":{"scanId":1,"reportCid":"bafyReport","reportHash":"',
            vm.toString(keccak256("report")),
            '","score":30,"verdict":2,"attestation":"0xc0ffee","deadline":2000000000}}'
        );
        assertEq(vm.eip712HashTypedData(json), _reportDigest(p));
    }

    // ------------------------------------------------------------ requestScanBySig

    function test_BySig_WithPermit_Gasless() public {
        ScanPayments.ScanRequest memory r = _req(user, PRICE, 0, block.timestamp + 1 hours);
        bytes memory sig = _sign(userPk, _reqDigest(r));
        ScanPayments.PermitSig memory p = _permit(user, userPk, PRICE, block.timestamp + 1 hours);
        vm.prank(relayer);
        uint256 id = sp.requestScanBySig(r, sig, p);
        assertEq(id, 1);
        assertEq(sp.nonces(user), 1);
        assertEq(token.balanceOf(treasury), PRICE / 2);
    }

    function test_BySig_Replay_Reverts() public {
        ScanPayments.ScanRequest memory r = _req(user, PRICE, 0, block.timestamp + 1 hours);
        bytes memory sig = _sign(userPk, _reqDigest(r));
        vm.prank(user);
        token.approve(address(sp), 10 * PRICE);
        vm.prank(relayer);
        sp.requestScanBySig(r, sig, noPermit);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(Nonces.InvalidAccountNonce.selector, user, 1));
        sp.requestScanBySig(r, sig, noPermit);
    }

    function test_BySig_WrongSigner_Expired_PriceAboveMax() public {
        vm.prank(user);
        token.approve(address(sp), 10 * PRICE);
        ScanPayments.ScanRequest memory r = _req(user, PRICE, 0, block.timestamp + 1 hours);
        bytes memory wrongSig = _sign(oraclePk, _reqDigest(r));
        vm.prank(relayer);
        vm.expectRevert(HolderCredits.InvalidSignature.selector);
        sp.requestScanBySig(r, wrongSig, noPermit);

        ScanPayments.ScanRequest memory expired = _req(user, PRICE, 0, block.timestamp - 1);
        bytes memory expiredSig = _sign(userPk, _reqDigest(expired));
        vm.prank(relayer);
        vm.expectRevert(ScanPayments.SignatureExpired.selector);
        sp.requestScanBySig(expired, expiredSig, noPermit);

        ScanPayments.ScanRequest memory cheap = _req(user, PRICE - 1, 0, block.timestamp + 1 hours);
        bytes memory cheapSig = _sign(userPk, _reqDigest(cheap));
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ScanPayments.PriceAboveMax.selector, PRICE, PRICE - 1));
        sp.requestScanBySig(cheap, cheapSig, noPermit);
    }

    function test_BySig_Erc1271Payer() public {
        MockERC1271Wallet wallet = new MockERC1271Wallet(user);
        token.mint(address(wallet), PRICE);
        wallet.approve(token, address(sp), PRICE);
        ScanPayments.ScanRequest memory r = _req(address(wallet), PRICE, 0, block.timestamp + 1 hours);
        bytes memory sig = _sign(userPk, _reqDigest(r));
        vm.prank(relayer);
        sp.requestScanBySig(r, sig, noPermit);
        assertEq(token.balanceOf(address(wallet)), 0);

        // signature from a key the wallet does not accept
        ScanPayments.ScanRequest memory r2 = _req(address(wallet), PRICE, 1, block.timestamp + 1 hours);
        bytes memory badSig = _sign(oraclePk, _reqDigest(r2));
        vm.prank(relayer);
        vm.expectRevert(HolderCredits.InvalidSignature.selector);
        sp.requestScanBySig(r2, badSig, noPermit);
    }

    function test_BySig_RelayerAllowlist_AndFeatureFlag() public {
        vm.prank(user);
        token.approve(address(sp), 10 * PRICE);
        vm.prank(owner);
        sp.setRelayerAllowlistEnabled(true);
        ScanPayments.ScanRequest memory r = _req(user, PRICE, 0, block.timestamp + 1 hours);
        bytes memory sig = _sign(userPk, _reqDigest(r));
        vm.prank(relayer);
        vm.expectRevert(ScanPayments.RelayerNotAllowed.selector);
        sp.requestScanBySig(r, sig, noPermit);
        vm.prank(user); // payer submitting its own request is always fine
        sp.requestScanBySig(r, sig, noPermit);

        uint8 bySig = sp.FEATURE_BY_SIG();
        vm.prank(owner);
        sp.setPausedFeatures(bySig);
        ScanPayments.ScanRequest memory r2 = _req(user, PRICE, 1, block.timestamp + 1 hours);
        bytes memory sig2 = _sign(userPk, _reqDigest(r2));
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ScanPayments.FeaturePaused.selector, 4));
        sp.requestScanBySig(r2, sig2, noPermit);
    }

    // ------------------------------------------------------------ publishReportBySig

    function test_PublishBySig_HappyPath_And_Replay() public {
        _pay(user);
        ScanPayments.PublishReport memory p = _report(1, block.timestamp + 1 hours);
        bytes memory sig = _sign(oraclePk, _reportDigest(p));
        vm.prank(relayer);
        sp.publishReportBySig(p, sig);
        (uint256 id, string memory cid,, uint8 risk, uint8 verdict,) = sp.latestReport(CHAIN, TARGET);
        assertEq(id, 1);
        assertEq(cid, "bafyReport");
        assertEq(risk, 30);
        assertEq(verdict, 2);
        assertTrue(sp.usedReportDigest(_reportDigest(p)));
        vm.prank(relayer);
        vm.expectRevert(ScanPayments.DigestUsed.selector);
        sp.publishReportBySig(p, sig);
    }

    function test_PublishBySig_WrongSigner_Expired_Relayer() public {
        _pay(user);
        ScanPayments.PublishReport memory p = _report(1, block.timestamp + 1 hours);
        bytes memory wrongSig = _sign(userPk, _reportDigest(p));
        bytes memory goodSig = _sign(oraclePk, _reportDigest(p));
        vm.prank(relayer);
        vm.expectRevert(HolderCredits.InvalidSignature.selector);
        sp.publishReportBySig(p, wrongSig);

        ScanPayments.PublishReport memory expired = _report(1, block.timestamp - 1);
        bytes memory expiredSig = _sign(oraclePk, _reportDigest(expired));
        vm.prank(relayer);
        vm.expectRevert(ScanPayments.SignatureExpired.selector);
        sp.publishReportBySig(expired, expiredSig);

        vm.prank(owner);
        sp.setRelayerAllowlistEnabled(true);
        vm.prank(relayer);
        vm.expectRevert(ScanPayments.RelayerNotAllowed.selector);
        sp.publishReportBySig(p, goodSig);
        vm.prank(owner);
        sp.setRelayer(relayer, true);
        vm.prank(relayer);
        sp.publishReportBySig(p, goodSig);
    }

    function test_PublishBySig_Erc1271Oracle() public {
        MockERC1271Wallet multisig = new MockERC1271Wallet(oracle);
        vm.prank(owner);
        sp.setOracle(address(multisig));
        _pay(user);
        ScanPayments.PublishReport memory p = _report(1, block.timestamp + 1 hours);
        bytes memory sig = _sign(oraclePk, _reportDigest(p));
        vm.prank(relayer);
        sp.publishReportBySig(p, sig);
        (uint256 id,,,,,) = sp.latestReport(CHAIN, TARGET);
        assertEq(id, 1);
    }
}
