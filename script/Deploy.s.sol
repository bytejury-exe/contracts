// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ScanPayments} from "../src/ScanPayments.sol";
import {ScanAuditRegistry} from "../src/ScanAuditRegistry.sol";
import {ScanAttestor} from "../src/ScanAttestor.sol";
import {ValidationRegistry} from "../src/erc8004/ValidationRegistry.sol";
import {IIdentityRegistry} from "../src/erc8004/IERC8004.sol";

/// @notice Deploys ScanPayments (+ optional ERC-7512 / ERC-8004 attestation stack).
///
/// Env (all optional except ORACLE):
///   OWNER, TREASURY      default 0x6998E1ebdB53A243D9D61Bb88C4426f42DF784D5
///   UTILITY_TOKEN        default TACITA test token 0xaa7cd9515df27f8947ace7c3eafe5a441818e828 (address(0) allowed)
///   SCAN_PRICE           default 1000e18 (placeholder, change later with setScanPrice)
///   ORACLE               backend publisher key (required)
///   DEPLOY_ATTESTATIONS  default true: deploy ScanAuditRegistry (+ ValidationRegistry / ScanAttestor, see below)
///   AUDITOR              ERC-7512 trusted signer, default ORACLE
///   IDENTITY_REGISTRY    ERC-8004 identity registry, default official 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432
///   VALIDATION_REGISTRY  reuse an existing ERC-8004 validation registry (default: deploy ours)
///   AGENT_ID             ERC-8004 agentId of our judge agent; when set, ScanAttestor is deployed
///   SCAN_CHAINS          comma-separated CAIP-2 scan target chains to enable (price 0 = default price),
///                        default DEFAULT_SCAN_CHAINS; the home chain eip155:<chainid> is always enabled by the constructor
/// If the broadcaster is OWNER it also enables SCAN_CHAINS and wires the report hook; if it owns AGENT_ID it
/// approves the attestor. Otherwise the owner must do these calls afterwards.
contract Deploy is Script {
    address internal constant DEFAULT_ADMIN = 0x6998E1ebdB53A243D9D61Bb88C4426f42DF784D5;
    address internal constant TACITA = 0xaA7cD9515dF27f8947ACe7c3eafe5a441818e828;
    address internal constant OFFICIAL_IDENTITY = 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432;
    /// @dev Scan targets (see shared/src/chains.ts). Payments stay on the deployment chain.
    string internal constant DEFAULT_SCAN_CHAINS =
        "eip155:1,eip155:42161,eip155:8453,solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";

    function run()
        external
        returns (ScanPayments sp, ScanAuditRegistry audits, ValidationRegistry validation, ScanAttestor attestor)
    {
        address owner = vm.envOr("OWNER", DEFAULT_ADMIN);
        address treasury = vm.envOr("TREASURY", DEFAULT_ADMIN);
        address token = vm.envOr("UTILITY_TOKEN", TACITA);
        uint256 price = vm.envOr("SCAN_PRICE", uint256(1000e18));
        address oracle = vm.envAddress("ORACLE");
        bool withAttestations = vm.envOr("DEPLOY_ATTESTATIONS", true);

        vm.startBroadcast();
        sp = new ScanPayments(owner, treasury, token, price, oracle);
        console2.log("ScanPayments", address(sp));
        string[] memory chains = vm.envOr("SCAN_CHAINS", ",", _split(DEFAULT_SCAN_CHAINS));
        for (uint256 i; i < chains.length; ++i) {
            if (msg.sender == owner) sp.setChainConfig(chains[i], true, 0);
            else console2.log("owner must call setChainConfig(chain, true, 0) for", chains[i]);
        }

        if (withAttestations) {
            audits = new ScanAuditRegistry(owner, vm.envOr("AUDITOR", oracle));
            console2.log("ScanAuditRegistry", address(audits));

            address identity = vm.envOr("IDENTITY_REGISTRY", OFFICIAL_IDENTITY);
            address existingValidation = vm.envOr("VALIDATION_REGISTRY", address(0));
            if (existingValidation == address(0)) {
                validation = new ValidationRegistry(identity);
                console2.log("ValidationRegistry", address(validation));
            } else {
                validation = ValidationRegistry(existingValidation);
            }

            if (vm.envExists("AGENT_ID")) {
                uint256 agentId = vm.envUint("AGENT_ID");
                attestor = new ScanAttestor(address(sp), address(audits), address(validation), agentId);
                console2.log("ScanAttestor", address(attestor));
                if (msg.sender == owner) sp.setReportHook(address(attestor));
                if (IIdentityRegistry(identity).ownerOf(agentId) == msg.sender) {
                    IAgentApprove(identity).approve(address(attestor), agentId);
                }
            }
        }

        // Holder tiers (thresholds TBD, all changeable from the admin panel). Example, kept disabled:
        //   HolderCredits.Tier[] memory tiers = new HolderCredits.Tier[](2);
        //   tiers[0] = HolderCredits.Tier({minBalance: 100_000e18, freeScansPerPeriod: 1, discountBps: 0});    // 1 free/day
        //   tiers[1] = HolderCredits.Tier({minBalance: 1_000_000e18, freeScansPerPeriod: 2, discountBps: 2000}); // 2 free/day
        //   sp.setTiers(tiers);
        //   sp.setCreditConfig(HolderCredits.CreditMode.ON_CHAIN_BALANCE, 1 days, 0, true);
        vm.stopBroadcast();
    }

    function _split(string memory csv) internal pure returns (string[] memory) {
        return vm.split(csv, ",");
    }
}

interface IAgentApprove {
    function approve(address to, uint256 tokenId) external;
}
