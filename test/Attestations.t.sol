// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {BaseTest} from "./Base.t.sol";
import {ScanAuditRegistry} from "../src/ScanAuditRegistry.sol";
import {ScanAttestor} from "../src/ScanAttestor.sol";
import {ValidationRegistry} from "../src/erc8004/ValidationRegistry.sol";
import {IERC7512} from "../src/interfaces/IERC7512.sol";
import {MockIdentityRegistry, MockERC1271Wallet} from "./mocks/MockAccounts.sol";

contract AttestationsTest is BaseTest, IERC7512 {
    ScanAuditRegistry internal registry;
    ValidationRegistry internal validation;
    MockIdentityRegistry internal identity;
    ScanAttestor internal attestor;
    address internal auditor;
    uint256 internal auditorPk;
    uint256 internal agentId;
    string internal targetStr;

    event ReportHookFailed(uint256 indexed scanId, bytes reason);
    event ValidationResponse(
        address indexed validatorAddress,
        uint256 indexed agentId,
        bytes32 indexed requestHash,
        uint8 response,
        string responseURI,
        bytes32 responseHash,
        string tag
    );

    function setUp() public override {
        super.setUp();
        (auditor, auditorPk) = makeAddrAndKey("auditor");
        registry = new ScanAuditRegistry(owner, auditor);
        identity = new MockIdentityRegistry();
        validation = new ValidationRegistry(address(identity));
        vm.prank(owner);
        agentId = identity.register("ipfs://judge.json");
        attestor = new ScanAttestor(address(sp), address(registry), address(validation), agentId);
        vm.startPrank(owner);
        identity.approve(address(attestor), agentId);
        sp.setReportHook(address(attestor));
        vm.stopPrank();
        targetStr = vm.toLowercase(vm.toString(address(token))); // scan our own mock token contract
    }

    // ------------------------------------------------------------ helpers

    function _summary(bytes32 auditHash, string memory uri) internal view returns (AuditSummary memory s) {
        string[] memory authors = new string[](2);
        authors[0] = "auditor:claude-opus-5.5";
        authors[1] = "judge:claude-opus-5.5";
        uint256[] memory ercs = new uint256[](2);
        ercs[0] = 20;
        ercs[1] = 2612;
        s = AuditSummary({
            auditor: Auditor("SCAM SCANER", "https://example.com", authors),
            issuedAt: block.timestamp,
            ercs: ercs,
            auditedContract: Contract(bytes32(uint256(4663)), address(token)),
            auditHash: auditHash,
            auditUri: uri
        });
    }

    function _signK1(AuditSummary memory s, uint256 pk) internal view returns (SignedAuditSummary memory) {
        bytes memory sig = _sign(pk, registry.hashAuditSummary(s));
        return SignedAuditSummary(s, block.timestamp, Signature(SignatureType.SECP256K1, sig));
    }

    // ------------------------------------------------------------ ERC-7512 registry

    function test_7512_DigestMatchesIndependentEip712() public view {
        AuditSummary memory s = _summary(keccak256("r"), "ipfs://cid");
        string memory json = string.concat(
            '{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"}],',
            '"Auditor":[{"name":"name","type":"string"},{"name":"uri","type":"string"},{"name":"authors","type":"string[]"}],',
            '"Contract":[{"name":"chainId","type":"bytes32"},{"name":"deployment","type":"address"}],',
            '"AuditSummary":[{"name":"auditor","type":"Auditor"},{"name":"issuedAt","type":"uint256"},',
            '{"name":"ercs","type":"uint256[]"},{"name":"auditedContract","type":"Contract"},',
            '{"name":"auditHash","type":"bytes32"},{"name":"auditUri","type":"string"}]},',
            '"primaryType":"AuditSummary","domain":{"name":"ERC-7652: Onchain Audit Representation","version":"1.0"},',
            '"message":{"auditor":{"name":"SCAM SCANER","uri":"https://example.com",',
            '"authors":["auditor:claude-opus-5.5","judge:claude-opus-5.5"]},"issuedAt":',
            vm.toString(block.timestamp),
            ',"ercs":[20,2612],"auditedContract":{"chainId":"',
            vm.toString(bytes32(uint256(4663))),
            '","deployment":"',
            vm.toString(address(token)),
            '"},"auditHash":"',
            vm.toString(keccak256("r")),
            '","auditUri":"ipfs://cid"}}'
        );
        assertEq(vm.eip712HashTypedData(json), registry.hashAuditSummary(s));
    }

    function test_7512_SubmitAndViews() public {
        SignedAuditSummary memory signed = _signK1(_summary(keccak256("r"), "ipfs://cid"), auditorPk);
        (address signer, bool trusted) = registry.verifyAudit(signed);
        assertEq(signer, auditor);
        assertTrue(trusted);

        vm.prank(stranger); // permissionless submission
        uint256 index = registry.submitAudit(signed);
        assertEq(index, 0);
        bytes32 chainId = bytes32(uint256(4663));
        assertEq(registry.auditCount(chainId, address(token)), 1);
        ScanAuditRegistry.AuditRecord memory rec = registry.latestAudit(chainId, address(token));
        assertEq(rec.signer, auditor);
        assertEq(rec.audit.summary.auditHash, keccak256("r"));
        assertEq(rec.audit.summary.auditor.authors[1], "judge:claude-opus-5.5");
        assertEq(rec.audit.summary.ercs[1], 2612);
        assertEq(registry.getAudit(chainId, address(token), 0).audit.summary.auditUri, "ipfs://cid");
        assertEq(registry.getAudits(chainId, address(token)).length, 1);

        vm.expectRevert(ScanAuditRegistry.AlreadyRecorded.selector);
        registry.submitAudit(signed);
    }

    function test_7512_Rejections() public {
        AuditSummary memory s = _summary(keccak256("r"), "ipfs://cid");
        // untrusted signer
        SignedAuditSummary memory bad = _signK1(s, userPk);
        vm.expectRevert(abi.encodeWithSelector(ScanAuditRegistry.UntrustedAuditor.selector, user));
        registry.submitAudit(bad);
        // malformed signature
        bad.auditorSignature.data = hex"1234";
        vm.expectRevert(ScanAuditRegistry.InvalidSignature.selector);
        registry.submitAudit(bad);
        // unsupported types
        bad.auditorSignature.sigType = SignatureType.BLS;
        vm.expectRevert(ScanAuditRegistry.UnsupportedSignatureType.selector);
        registry.submitAudit(bad);
        bad.auditorSignature.sigType = SignatureType.SECP256R1;
        vm.expectRevert(ScanAuditRegistry.UnsupportedSignatureType.selector);
        registry.submitAudit(bad);
        // timestamps
        SignedAuditSummary memory future = _signK1(s, auditorPk);
        future.signedAt = block.timestamp + 1;
        vm.expectRevert(ScanAuditRegistry.InvalidTimestamps.selector);
        registry.submitAudit(future);
        future.signedAt = s.issuedAt - 1;
        vm.expectRevert(ScanAuditRegistry.InvalidTimestamps.selector);
        registry.submitAudit(future);
        // no audit yet
        vm.expectRevert(ScanAuditRegistry.NoAudit.selector);
        registry.latestAudit(bytes32(uint256(1)), address(1));
        // distrusted auditor
        SignedAuditSummary memory good = _signK1(s, auditorPk);
        vm.prank(owner);
        registry.setAuditor(auditor, false);
        vm.expectRevert(abi.encodeWithSelector(ScanAuditRegistry.UntrustedAuditor.selector, auditor));
        registry.submitAudit(good);
    }

    function test_7512_Erc1271Auditor() public {
        MockERC1271Wallet wallet = new MockERC1271Wallet(auditor);
        vm.prank(owner);
        registry.setAuditor(address(wallet), true);
        AuditSummary memory s = _summary(keccak256("r"), "ipfs://cid");
        bytes memory inner = _sign(auditorPk, registry.hashAuditSummary(s));
        bytes memory data = abi.encode(uint256(4663), address(wallet), block.number, inner);
        SignedAuditSummary memory signed =
            SignedAuditSummary(s, block.timestamp, Signature(SignatureType.ERC1271, data));
        registry.submitAudit(signed);
        assertEq(registry.latestAudit(bytes32(uint256(4663)), address(token)).signer, address(wallet));

        // wrong chain id / future block / EOA account / bad inner signature
        AuditSummary memory s2 = _summary(keccak256("r2"), "ipfs://cid2");
        bytes memory inner2 = _sign(auditorPk, registry.hashAuditSummary(s2));
        bytes[4] memory bads = [
            abi.encode(uint256(1), address(wallet), block.number, inner2),
            abi.encode(uint256(4663), address(wallet), block.number + 1, inner2),
            abi.encode(uint256(4663), auditor, block.number, inner2),
            abi.encode(uint256(4663), address(wallet), block.number, _sign(userPk, registry.hashAuditSummary(s2)))
        ];
        for (uint256 i; i < 4; ++i) {
            vm.expectRevert(ScanAuditRegistry.InvalidSignature.selector);
            registry.submitAudit(SignedAuditSummary(s2, block.timestamp, Signature(SignatureType.ERC1271, bads[i])));
        }
    }

    function test_7512_Admin() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        registry.setAuditor(stranger, true);
        vm.startPrank(owner);
        vm.expectRevert(ScanAuditRegistry.ZeroAddress.selector);
        registry.setAuditor(address(0), true);
        vm.expectRevert(ScanAuditRegistry.RenounceDisabled.selector);
        registry.renounceOwnership();
        vm.stopPrank();
        ScanAuditRegistry noInitial = new ScanAuditRegistry(owner, address(0));
        assertFalse(noInitial.isAuditor(address(0)));
    }

    // ------------------------------------------------------------ ERC-8004 validation registry

    function test_8004_RequestResponseAndViews() public {
        address validator = makeAddr("validator");
        bytes32 rh = keccak256("req");
        vm.prank(stranger);
        vm.expectRevert(ValidationRegistry.NotAuthorized.selector);
        validation.validationRequest(validator, agentId, "uri", rh);
        vm.prank(owner);
        vm.expectRevert(ValidationRegistry.ZeroAddress.selector);
        validation.validationRequest(address(0), agentId, "uri", rh);

        vm.prank(owner);
        validation.validationRequest(validator, agentId, "uri", rh);
        vm.prank(owner);
        vm.expectRevert(ValidationRegistry.RequestExists.selector);
        validation.validationRequest(validator, agentId, "uri", rh);

        vm.prank(stranger);
        vm.expectRevert(ValidationRegistry.NotValidator.selector);
        validation.validationResponse(rh, 50, "", 0, "");
        vm.prank(validator);
        vm.expectRevert(ValidationRegistry.InvalidResponse.selector);
        validation.validationResponse(rh, 101, "", 0, "");
        vm.expectRevert(ValidationRegistry.UnknownRequest.selector);
        validation.validationResponse(keccak256("nope"), 1, "", 0, "");
        vm.expectRevert(ValidationRegistry.UnknownRequest.selector);
        validation.getValidationStatus(keccak256("nope"));

        // unanswered requests are not counted
        (uint64 count,) = validation.getSummary(agentId, new address[](0), "");
        assertEq(count, 0);

        vm.prank(validator);
        validation.validationResponse(rh, 80, "ipfs://x", bytes32(uint256(1)), "soft");
        vm.prank(validator);
        validation.validationResponse(rh, 90, "ipfs://x", bytes32(uint256(2)), "hard"); // progressive update
        (address v, uint256 a, uint8 resp, bytes32 respHash, string memory tag, uint256 at) =
            validation.getValidationStatus(rh);
        assertEq(v, validator);
        assertEq(a, agentId);
        assertEq(resp, 90);
        assertEq(respHash, bytes32(uint256(2)));
        assertEq(tag, "hard");
        assertEq(at, block.timestamp);
        assertEq(validation.getAgentValidations(agentId)[0], rh);
        assertEq(validation.getValidatorRequests(validator)[0], rh);
        assertEq(validation.getIdentityRegistry(), address(identity));

        // operator via setApprovalForAll can also request
        vm.prank(owner);
        identity.setApprovalForAll(stranger, true);
        vm.prank(stranger);
        validation.validationRequest(validator, agentId, "uri2", keccak256("req2"));
        vm.prank(validator);
        validation.validationResponse(keccak256("req2"), 50, "", 0, "hard");

        address[] memory filter = new address[](1);
        filter[0] = validator;
        uint8 avg;
        (count, avg) = validation.getSummary(agentId, filter, "hard");
        assertEq(count, 2);
        assertEq(avg, 70);
        (count,) = validation.getSummary(agentId, new address[](0), "soft");
        assertEq(count, 0);
        filter[0] = stranger;
        (count, avg) = validation.getSummary(agentId, filter, "");
        assertEq(count, 0);
        assertEq(avg, 0);
    }

    function test_8004_ConstructorZero() public {
        vm.expectRevert(ValidationRegistry.ZeroAddress.selector);
        new ValidationRegistry(address(0));
    }

    // ------------------------------------------------------------ ScanAttestor (publish path)

    function test_Attestor_FullFlow_7512And8004() public {
        uint256 scanId = _pay(user, targetStr);
        bytes32 reportHash = keccak256("report-json");
        SignedAuditSummary memory signed = _signK1(_summary(reportHash, "ipfs://bafyReport"), auditorPk);
        bytes32 requestHash = attestor.validationRequestHash(scanId, reportHash);

        vm.expectEmit(address(validation));
        emit ValidationResponse(address(attestor), agentId, requestHash, 75, "ipfs://bafyReport", reportHash, "CAUTION");
        vm.prank(oracle);
        sp.publishReportWithAttestation(scanId, "bafyReport", reportHash, 75, 2, abi.encode(signed));

        // ERC-7512 record
        ScanAuditRegistry.AuditRecord memory rec = registry.latestAudit(bytes32(uint256(4663)), address(token));
        assertEq(rec.audit.summary.auditHash, reportHash);
        assertEq(rec.signer, auditor);
        // ERC-8004 validation
        (address v, uint256 a, uint8 resp,, string memory tag,) = validation.getValidationStatus(requestHash);
        assertEq(v, address(attestor));
        assertEq(a, agentId);
        assertEq(resp, 75);
        assertEq(tag, "CAUTION");
        assertTrue(attestor.validationRequested(requestHash));

        // same scan re-published with the same hash: only a new response, no duplicate request
        vm.prank(oracle);
        sp.publishReport(scanId, "bafyReport", reportHash, 10, 4);
        (,, resp,, tag,) = validation.getValidationStatus(requestHash);
        assertEq(resp, 10);
        assertEq(tag, "SCAM");
        assertEq(validation.getAgentValidations(agentId).length, 1);
    }

    function test_Attestor_MismatchedAudit_HookFailsButReportStored() public {
        uint256 scanId = _pay(user, targetStr);
        bytes32 reportHash = keccak256("report-json");
        SignedAuditSummary memory wrongHash = _signK1(_summary(keccak256("other"), "ipfs://bafyReport"), auditorPk);
        vm.expectEmit(address(sp));
        emit ReportHookFailed(scanId, abi.encodeWithSelector(ScanAttestor.AuditMismatch.selector));
        vm.prank(oracle);
        sp.publishReportWithAttestation(scanId, "bafyReport", reportHash, 25, 2, abi.encode(wrongHash));
        (uint256 id,,,,,) = sp.latestReport(CHAIN, targetStr);
        assertEq(id, scanId);
        assertEq(registry.auditCount(bytes32(uint256(4663)), address(token)), 0);
    }

    function test_Attestor_WrongUriOrTarget_Mismatch() public {
        uint256 scanId = _pay(user, targetStr);
        bytes32 reportHash = keccak256("report-json");
        bytes memory att = abi.encode(_signK1(_summary(reportHash, "ipfs://different"), auditorPk));
        vm.expectEmit(address(sp));
        emit ReportHookFailed(scanId, abi.encodeWithSelector(ScanAttestor.AuditMismatch.selector));
        vm.prank(oracle);
        sp.publishReportWithAttestation(scanId, "bafyReport", reportHash, 0, 1, att);

        uint256 scan2 = _pay(user); // TARGET != token address
        att = abi.encode(_signK1(_summary(reportHash, "ipfs://bafyReport"), auditorPk));
        vm.expectEmit(address(sp));
        emit ReportHookFailed(scan2, abi.encodeWithSelector(ScanAttestor.AuditMismatch.selector));
        vm.prank(oracle);
        sp.publishReportWithAttestation(scan2, "bafyReport", reportHash, 0, 1, att);
    }

    function test_Attestor_OnlyScanPayments_AndVerdictNames() public {
        vm.expectRevert(ScanAttestor.OnlyScanPayments.selector);
        attestor.onReportPublished(1, 0, "", 0, 0, 0, "");
        assertEq(attestor.verdictName(0), "UNKNOWN");
        assertEq(attestor.verdictName(1), "SAFE");
        assertEq(attestor.verdictName(3), "HIGH_RISK");
        assertEq(attestor.evmTargetKey(bytes32(uint256(4663)), address(token)), sp.targetKey(CHAIN, targetStr));
        vm.expectRevert(ScanAttestor.ZeroAddress.selector);
        new ScanAttestor(address(0), address(0), address(0), 0);
    }

    function test_Attestor_ValidationOnly_NoRegistries() public {
        ScanAttestor bare = new ScanAttestor(address(sp), address(0), address(0), 0);
        vm.prank(owner);
        sp.setReportHook(address(bare));
        uint256 scanId = _pay(user);
        vm.recordLogs();
        vm.prank(oracle);
        sp.publishReportWithAttestation(scanId, "cid", 0, 0, 1, hex"01");
        assertEq(vm.getRecordedLogs().length, 1, "only ReportPublished, hook did nothing");
    }

    function test_Attestor_NotApprovedOnIdentity_HookFails() public {
        vm.prank(owner);
        identity.approve(address(0), agentId);
        uint256 scanId = _pay(user);
        vm.expectEmit(address(sp));
        emit ReportHookFailed(scanId, abi.encodeWithSelector(ValidationRegistry.NotAuthorized.selector));
        vm.prank(oracle);
        sp.publishReport(scanId, "cid", 0, 0, 1);
    }

    function test_7512_DomainSeparator() public view {
        assertEq(
            registry.DOMAIN_SEPARATOR(),
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version)"),
                    keccak256("ERC-7652: Onchain Audit Representation"),
                    keccak256("1.0")
                )
            )
        );
    }
}
