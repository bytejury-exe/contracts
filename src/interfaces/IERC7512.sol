// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ERC-7512 data types (Onchain Representation for Audits, status: Draft)
/// @notice Mirrors the spec's structs. Solidity has no struct inheritance, so the spec's
///         `SignedAuditSummary extends AuditSummary` is modelled as a struct that embeds `summary`.
/// @dev https://eips.ethereum.org/EIPS/eip-7512
interface IERC7512 {
    struct Auditor {
        string name;
        string uri;
        string[] authors;
    }

    struct Contract {
        bytes32 chainId;
        address deployment;
    }

    struct AuditSummary {
        Auditor auditor;
        uint256 issuedAt;
        uint256[] ercs;
        Contract auditedContract;
        bytes32 auditHash;
        string auditUri;
    }

    enum SignatureType {
        SECP256K1,
        BLS,
        ERC1271,
        SECP256R1
    }

    struct Signature {
        SignatureType sigType;
        bytes data;
    }

    struct SignedAuditSummary {
        AuditSummary summary;
        uint256 signedAt;
        Signature auditorSignature;
    }
}
