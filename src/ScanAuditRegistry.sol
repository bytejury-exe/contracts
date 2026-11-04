// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC7512} from "./interfaces/IERC7512.sol";

/// @title ScanAuditRegistry
/// @notice ERC-7512 (Onchain Representation for Audits) registry for the scanner's verdicts.
///         Anyone may submit a SignedAuditSummary, but it is only stored when its EIP-712 signature was produced by an
///         auditor key the owner trusts. Records are append-only; distrusting a key later is visible via `isAuditor`.
/// @dev Separate contract (not inside ScanPayments) because the spec mandates its own EIP-712 domain
///      `EIP712Domain(string name,string version)` without chainId / verifyingContract, which makes signatures
///      portable between registries, and because ScanPayments is close to the 24 KB code-size limit.
///      Supported signature types: SECP256K1 (65-byte r,s,v) and ERC1271 (abi.encode(chainId, account, blockNumber,
///      signature), verified against the account on this chain). BLS / SECP256R1 are rejected.
contract ScanAuditRegistry is IERC7512, Ownable2Step {
    struct AuditRecord {
        SignedAuditSummary audit;
        address signer;
        uint64 recordedAt;
    }

    /// @notice Domain name exactly as written in the ERC-7512 text ("ERC-7652" is verbatim from the spec).
    string public constant DOMAIN_NAME = "ERC-7652: Onchain Audit Representation";
    string public constant DOMAIN_VERSION = "1.0";

    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version)");
    bytes32 public constant AUDITOR_TYPEHASH = keccak256("Auditor(string name,string uri,string[] authors)");
    bytes32 public constant CONTRACT_TYPEHASH = keccak256("Contract(bytes32 chainId,address deployment)");
    bytes32 public constant AUDIT_SUMMARY_TYPEHASH = keccak256(
        "AuditSummary(Auditor auditor,uint256 issuedAt,uint256[] ercs,Contract auditedContract,bytes32 auditHash,string auditUri)"
        "Auditor(string name,string uri,string[] authors)Contract(bytes32 chainId,address deployment)"
    );

    /// @notice Keys whose signatures are accepted.
    mapping(address auditor => bool) public isAuditor;
    /// @notice Typed-data digests already recorded (prevents duplicates).
    mapping(bytes32 digest => bool) public recorded;
    mapping(bytes32 contractKey => AuditRecord[]) internal _audits;

    event AuditorSet(address indexed auditor, bool trusted);
    event AuditRecorded(
        bytes32 indexed chainId, address indexed deployment, address indexed signer, uint256 index, bytes32 auditHash
    );

    error ZeroAddress();
    error UnsupportedSignatureType();
    error InvalidSignature();
    error UntrustedAuditor(address signer);
    error AlreadyRecorded();
    error InvalidTimestamps();
    error NoAudit();
    error RenounceDisabled();

    constructor(address initialOwner, address initialAuditor) Ownable(initialOwner) {
        if (initialAuditor != address(0)) {
            isAuditor[initialAuditor] = true;
            emit AuditorSet(initialAuditor, true);
        }
    }

    // ------------------------------------------------------------------ admin

    function setAuditor(address auditor, bool trusted) external onlyOwner {
        if (auditor == address(0)) revert ZeroAddress();
        isAuditor[auditor] = trusted;
        emit AuditorSet(auditor, trusted);
    }

    /// @notice Disabled: trusted-auditor management always needs an admin.
    function renounceOwnership() public pure override {
        revert RenounceDisabled();
    }

    // ------------------------------------------------------------------ write

    /// @notice Store a signed audit summary. Reverts unless signed by a trusted auditor.
    /// @return index Position in the audited contract's audit list.
    function submitAudit(SignedAuditSummary memory signed) external returns (uint256 index) {
        AuditSummary memory s = signed.summary;
        if (signed.signedAt > block.timestamp || s.issuedAt > signed.signedAt) revert InvalidTimestamps();
        bytes32 digest = hashAuditSummary(s);
        if (recorded[digest]) revert AlreadyRecorded();
        address signer = _recoverSigner(digest, signed.auditorSignature);
        if (!isAuditor[signer]) revert UntrustedAuditor(signer);
        recorded[digest] = true;

        AuditRecord[] storage list = _audits[_contractKey(s.auditedContract.chainId, s.auditedContract.deployment)];
        index = list.length;
        AuditRecord storage rec = list.push();
        rec.audit = signed;
        rec.signer = signer;
        rec.recordedAt = uint64(block.timestamp);
        emit AuditRecorded(s.auditedContract.chainId, s.auditedContract.deployment, signer, index, s.auditHash);
    }

    // ------------------------------------------------------------------ views

    /// @notice Verify a signed summary without storing it.
    /// @return signer  Recovered auditor key (reverts if the signature is malformed / invalid).
    /// @return trusted Whether `signer` is currently a trusted auditor.
    function verifyAudit(SignedAuditSummary memory signed) external view returns (address signer, bool trusted) {
        signer = _recoverSigner(hashAuditSummary(signed.summary), signed.auditorSignature);
        trusted = isAuditor[signer];
    }

    function auditCount(bytes32 chainId, address deployment) external view returns (uint256) {
        return _audits[_contractKey(chainId, deployment)].length;
    }

    function getAudit(bytes32 chainId, address deployment, uint256 index) external view returns (AuditRecord memory) {
        return _audits[_contractKey(chainId, deployment)][index];
    }

    function getAudits(bytes32 chainId, address deployment) external view returns (AuditRecord[] memory) {
        return _audits[_contractKey(chainId, deployment)];
    }

    function latestAudit(bytes32 chainId, address deployment) external view returns (AuditRecord memory) {
        AuditRecord[] storage list = _audits[_contractKey(chainId, deployment)];
        if (list.length == 0) revert NoAudit();
        return list[list.length - 1];
    }

    /// @notice ERC-7512 EIP-712 domain separator.
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() public pure returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(DOMAIN_NAME)), keccak256(bytes(DOMAIN_VERSION))));
    }

    /// @notice EIP-712 digest an auditor signs for `s`.
    function hashAuditSummary(AuditSummary memory s) public pure returns (bytes32) {
        bytes32[] memory authorHashes = new bytes32[](s.auditor.authors.length);
        for (uint256 i; i < authorHashes.length; ++i) {
            authorHashes[i] = keccak256(bytes(s.auditor.authors[i]));
        }
        bytes32 auditorHash = keccak256(
            abi.encode(
                AUDITOR_TYPEHASH,
                keccak256(bytes(s.auditor.name)),
                keccak256(bytes(s.auditor.uri)),
                keccak256(abi.encodePacked(authorHashes))
            )
        );
        bytes32 contractHash =
            keccak256(abi.encode(CONTRACT_TYPEHASH, s.auditedContract.chainId, s.auditedContract.deployment));
        bytes32 structHash = keccak256(
            abi.encode(
                AUDIT_SUMMARY_TYPEHASH,
                auditorHash,
                s.issuedAt,
                keccak256(abi.encodePacked(s.ercs)),
                contractHash,
                s.auditHash,
                keccak256(bytes(s.auditUri))
            )
        );
        return MessageHashUtils.toTypedDataHash(DOMAIN_SEPARATOR(), structHash);
    }

    // ------------------------------------------------------------------ internal

    function _recoverSigner(bytes32 digest, Signature memory sig) internal view returns (address signer) {
        if (sig.sigType == SignatureType.SECP256K1) {
            (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig.data);
            if (err != ECDSA.RecoverError.NoError) revert InvalidSignature();
            return recovered;
        }
        if (sig.sigType == SignatureType.ERC1271) {
            (uint256 chainId, address account, uint256 blockNumber, bytes memory inner) =
                abi.decode(sig.data, (uint256, address, uint256, bytes));
            if (chainId != block.chainid || blockNumber > block.number || account.code.length == 0) {
                revert InvalidSignature();
            }
            (bool ok, bytes memory ret) = account.staticcall(abi.encodeCall(IERC1271.isValidSignature, (digest, inner)));
            if (!ok || ret.length < 32 || abi.decode(ret, (bytes4)) != IERC1271.isValidSignature.selector) {
                revert InvalidSignature();
            }
            return account;
        }
        revert UnsupportedSignatureType();
    }

    function _contractKey(bytes32 chainId, address deployment) internal pure returns (bytes32) {
        return keccak256(abi.encode(chainId, deployment));
    }
}
