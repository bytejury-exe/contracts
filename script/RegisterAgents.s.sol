// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";

interface IAgentIdentity {
    function register(string calldata agentURI) external returns (uint256 agentId);
}

/// @notice Registers our AI agents on the ERC-8004 Identity Registry (official singleton on Robinhood Chain).
/// Env:
///   AGENT_URIS         comma-separated agent registration URIs (pin the erc8004/*.json registration files to IPFS first),
///                      e.g. "ipfs://<site-analyst>,ipfs://<auditor>,ipfs://<osint>,ipfs://<prosecutor>,ipfs://<judge>"
///   IDENTITY_REGISTRY  default 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432
/// After registering, add {"agentId", "agentRegistry": "eip155:4663:<registry>"} to each JSON's `registrations`,
/// re-pin and call setAgentURI. Use the judge's agentId as AGENT_ID for Deploy.s.sol.
contract RegisterAgents is Script {
    function run() external returns (uint256[] memory ids) {
        address identity = vm.envOr("IDENTITY_REGISTRY", address(0x8004A169FB4a3325136EB29fA0ceB6D2e539a432));
        string[] memory uris = vm.envString("AGENT_URIS", ",");
        ids = new uint256[](uris.length);
        vm.startBroadcast();
        for (uint256 i; i < uris.length; ++i) {
            ids[i] = IAgentIdentity(identity).register(uris[i]);
            console2.log(uris[i], ids[i]);
        }
        vm.stopBroadcast();
    }
}
