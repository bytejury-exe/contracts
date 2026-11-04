// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IReportHook
/// @notice Optional add-on that ScanPayments notifies after a report is stored (e.g. ERC-7512 / ERC-8004 attestations).
/// @dev ScanPayments calls the hook inside try/catch: a failing hook never blocks report publishing.
interface IReportHook {
    /// @param scanId     Scan the report belongs to.
    /// @param targetKey  keccak256(abi.encodePacked(chain, ":", target)) of the scanned target.
    /// @param reportCid  IPFS CID of the report JSON.
    /// @param reportHash keccak256 of the report JSON.
    /// @param score      Safety score 0-100, higher is safer.
    /// @param verdict    0 UNKNOWN, 1 SAFE, 2 CAUTION, 3 HIGH_RISK, 4 SCAM.
    /// @param attestation Opaque, hook-specific payload supplied by the oracle (may be empty).
    function onReportPublished(
        uint256 scanId,
        bytes32 targetKey,
        string calldata reportCid,
        bytes32 reportHash,
        uint8 score,
        uint8 verdict,
        bytes calldata attestation
    ) external;
}
