// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {IReportHook} from "./interfaces/IReportHook.sol";
import {IERC7512} from "./interfaces/IERC7512.sol";
import {ScanAuditRegistry} from "./ScanAuditRegistry.sol";
import {IValidationRegistry} from "./erc8004/IERC8004.sol";

/// @title ScanAttestor
/// @notice Report hook for ScanPayments that turns every published report into standard attestations:
///         - ERC-7512: if the oracle passes `attestation = abi.encode(SignedAuditSummary)`, it is checked against the
///           report (auditHash == reportHash, auditUri == "ipfs://<cid>", audited contract == scanned target) and
///           stored in the ScanAuditRegistry (which verifies the auditor signature);
///         - ERC-8004: records a validation request for our auditor agent (`agentId`) and answers it with
///           response = score (safety score 0-100, higher is safer), responseURI = report URI, responseHash = reportHash,
///           tag = verdict name.
/// @dev Immutable configuration and no admin: to change registries or agent, deploy a new attestor and point
///      `ScanPayments.setReportHook` to it. The agent owner must approve this contract as operator of `agentId`
///      on the Identity Registry (`approve` or `setApprovalForAll`).
contract ScanAttestor is IReportHook, IERC7512 {
    address public immutable scanPayments;
    ScanAuditRegistry public immutable auditRegistry;
    IValidationRegistry public immutable validationRegistry;
    uint256 public immutable agentId;

    /// @notice ERC-8004 requests already opened (re-published reports only add a new response).
    mapping(bytes32 requestHash => bool) public validationRequested;

    error OnlyScanPayments();
    error ZeroAddress();
    error AuditMismatch();

    constructor(address scanPayments_, address auditRegistry_, address validationRegistry_, uint256 agentId_) {
        if (scanPayments_ == address(0)) revert ZeroAddress();
        scanPayments = scanPayments_;
        auditRegistry = ScanAuditRegistry(auditRegistry_);
        validationRegistry = IValidationRegistry(validationRegistry_);
        agentId = agentId_;
    }

    /// @inheritdoc IReportHook
    function onReportPublished(
        uint256 scanId,
        bytes32 targetKey,
        string calldata reportCid,
        bytes32 reportHash,
        uint8 score,
        uint8 verdict,
        bytes calldata attestation
    ) external {
        if (msg.sender != scanPayments) revert OnlyScanPayments();
        string memory uri = string.concat("ipfs://", reportCid);

        // ERC-8004 validation (state is written before any external call)
        if (address(validationRegistry) != address(0)) {
            bytes32 requestHash = validationRequestHash(scanId, reportHash);
            if (!validationRequested[requestHash]) {
                validationRequested[requestHash] = true;
                validationRegistry.validationRequest(address(this), agentId, uri, requestHash);
            }
            validationRegistry.validationResponse(requestHash, score, uri, reportHash, verdictName(verdict));
        }

        // ERC-7512 audit summary (optional)
        if (attestation.length != 0 && address(auditRegistry) != address(0)) {
            SignedAuditSummary memory signed = abi.decode(attestation, (SignedAuditSummary));
            AuditSummary memory s = signed.summary;
            if (
                s.auditHash != reportHash || keccak256(bytes(s.auditUri)) != keccak256(bytes(uri))
                    || evmTargetKey(s.auditedContract.chainId, s.auditedContract.deployment) != targetKey
            ) revert AuditMismatch();
            auditRegistry.submitAudit(signed);
        }
    }

    /// @notice ERC-8004 requestHash used for a scan's report.
    function validationRequestHash(uint256 scanId, bytes32 reportHash) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, scanPayments, scanId, reportHash));
    }

    /// @notice ScanPayments targetKey of an EVM contract: keccak256("eip155:<chainId>:<lowercase 0x address>").
    function evmTargetKey(bytes32 chainId, address deployment) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "eip155:",
                Strings.toString(uint256(chainId)),
                ":",
                Strings.toHexString(uint256(uint160(deployment)), 20)
            )
        );
    }

    function verdictName(uint8 verdict) public pure returns (string memory) {
        if (verdict == 1) return "SAFE";
        if (verdict == 2) return "CAUTION";
        if (verdict == 3) return "HIGH_RISK";
        if (verdict == 4) return "SCAM";
        return "UNKNOWN";
    }
}
