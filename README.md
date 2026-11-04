<p align="center">
  <img src="assets/logo-512.png" width="112" alt="BYTEJURY shield logo" />
</p>

<h1 align="center">BYTEJURY contracts</h1>

<p align="center">
  <b>AI cybersecurity audits by AI agents.</b> Claims lie. Code doesn't.<br />
  The on-chain side of <a href="https://bytejury.xyz">bytejury.xyz</a>: payments, burns, holder credits and audit attestations.
</p>

<p align="center">
  <a href="../../actions/workflows/test.yml"><img src="../../actions/workflows/test.yml/badge.svg" alt="tests" /></a>
  <img src="https://img.shields.io/badge/license-MIT-0b7a78" alt="MIT license" />
  <img src="https://img.shields.io/badge/solidity-0.8.30-0a1a7a" alt="Solidity 0.8.30" />
  <img src="https://img.shields.io/badge/chain-Robinhood%20Chain%204663-ffd800?labelColor=000" alt="Robinhood Chain" />
  <img src="https://img.shields.io/badge/verified-Blockscout-139a2f" alt="verified on Blockscout" />
</p>

---

BYTEJURY audits other people's smart contracts. These are **ours**, in the open, so you can check the part that touches
your money yourself.

## Check it yourself

| What we say | Where to check |
|---|---|
| The code here is the code that runs | Every deployed contract is verified on Blockscout. The sources in `src/` are identical to the verified sources, file for file. |
| Part of every audit fee is burned | `ScanPayments._distribute()` burns `burnBps` of what it receives in the **same transaction** (via `burn()`, or by sending to `0x…dEaD`). Current setting: `burnBps()` = 5000 (50%). |
| The contract does not sit on your tokens | A payment is pulled and forwarded to burn / treasury atomically. Between transactions the contract holds nothing. |
| Nothing can be swapped out from under you | No proxies, no upgrade path. A new version would be a new deployment, at a new address. |
| Every admin change is public | Each setter emits an event (`BurnBpsChanged`, `TreasuryChanged`, `UtilityTokenChanged`, `ScanPriceChanged`, …). |
| Our AI jury has an on-chain identity | Agent **#20727** in the official ERC-8004 Identity Registry. Its registration file is in [`erc8004/`](erc8004/). |

## What the owner can and cannot do

We publish this the same way we publish it for every project we audit.

| The owner **can** | The owner **cannot** |
|---|---|
| change the burn share (`setBurnBps`, 0–100%, event `BurnBpsChanged`) | change the code: no proxy, no upgrade |
| change the treasury address (`setTreasury`) | take tokens in flight: payments are forwarded in the same transaction |
| switch the utility token (`setUtilityToken`, one token at a time) | renounce ownership by accident (`renounceOwnership` is disabled) |
| set the price, rescan policy and supported chains (operator role) | hand ownership over in one step (`Ownable2Step`: the new owner must accept) |
| pause new scan requests (`pause`; only the owner can `unpause`) | |
| set the oracle that publishes reports and the auditor keys trusted by the ERC-7512 registry | |
| recover tokens sent to the contract **by mistake** (`rescueTokens`) | |

The burn share is a setting, not a constant, so anyone can watch it: read `burnBps()` on the explorer, or follow the
`BurnBpsChanged` events.

## Deployed on Robinhood Chain (chain id 4663)

| Contract | Address | What it does |
|---|---|---|
| `ScanPayments` | [`0x9F20472903486F732C9861E516c1C238Fd2e56B3`](https://robinhoodchain.blockscout.com/address/0x9F20472903486F732C9861E516c1C238Fd2e56B3) | Pay per audit, burn / treasury split, holder free scans, report registry |
| `ScanAuditRegistry` | [`0x2a3D67A51dD7D8aA574Ed69F99c11a6195f0496D`](https://robinhoodchain.blockscout.com/address/0x2a3D67A51dD7D8aA574Ed69F99c11a6195f0496D) | ERC-7512 registry of signed audit summaries |
| `ValidationRegistry` | [`0xCf244A61A2B7EefF005B82FbD4f26Fff6c8c1e4a`](https://robinhoodchain.blockscout.com/address/0xCf244A61A2B7EefF005B82FbD4f26Fff6c8c1e4a) | ERC-8004 Validation Registry (none existed on this chain) |
| `ScanAttestor` | [`0x63974DA2979b3dA762204d25d080c46E96aB7656`](https://robinhoodchain.blockscout.com/address/0x63974DA2979b3dA762204d25d080c46E96aB7656) | Report hook: writes the ERC-7512 summary and the ERC-8004 validation response |
| ERC-8004 Identity Registry (official) | [`0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`](https://robinhoodchain.blockscout.com/address/0x8004A169FB4a3325136EB29fA0ceB6D2e539a432) | Holds agent #20727, "BYTEJURY Jury" |

`ScanPayments` was deployed at block 105,415,838. The `$BJRY` token address will be listed here once the contract points to it.

## How a paid audit works

1. You pick what to audit on [bytejury.xyz](https://bytejury.xyz) and approve the exact price (never an unlimited allowance).
2. `requestScan` pulls the price, burns `burnBps` of it, sends the rest to the treasury and emits `ScanRequested`.
3. The scanner picks the event up and five AI agents audit the target: the code, every related contract, a fork
   simulation and every claim on the project's site and X.
4. The report is published once and stays public for everyone. Holders above a tier get free scans
   (`requestFreeScan` / `requestFreeScanWithVoucher`), with no tokens moved.

---

## For developers

Foundry, solc 0.8.30 (`evm_version = cancun`, optimizer 200 runs), OpenZeppelin Contracts v5.4.0.

```bash
forge install foundry-rs/forge-std OpenZeppelin/openzeppelin-contracts@v5.4.0
forge build --sizes
forge test                                                        # unit + fuzz tests
ROBINHOOD_RPC_URL=https://rpc.mainnet.chain.robinhood.com forge test --match-contract ForkTest
```

| Path | Contents |
|---|---|
| `src/ScanPayments.sol` | Payments, burn / treasury split, EIP-712 gasless paths (`requestScanBySig`, `publishReportBySig`), reports |
| `src/HolderCredits.sol` | Holder tiers, credit modes (on-chain balance or signed voucher), manual credits |
| `src/ScanRoles.sol` | `Ownable2Step` owner + operator and credit-manager roles, renounce disabled |
| `src/ScanAuditRegistry.sol` | ERC-7512 `SignedAuditSummary` registry (SECP256K1 or ERC-1271 auditor keys) |
| `src/erc8004/` | Minimal ERC-8004 Validation Registry and interfaces |
| `src/ScanAttestor.sol` | Report hook that writes the attestations on publish |
| `test/` | Unit, fuzz, signature and fork tests |
| `script/` | Deployment and ERC-8004 agent registration scripts |
| `erc8004/` | Registration file of agent #20727 (pinned on IPFS) |

<details>
<summary>Payment split, EIP-712 types and credit modes</summary>

`quote(payer, chain, target)` = chain price override (or `scanPrice`) × `rescanPriceBps` if the target already has a
report, minus the holder-tier discount. The amount actually **received** (fee-on-transfer safe) is split:
`burn = received * burnBps / 10000` (via `burn(uint256)` if it really lowers the balance, else sent to `0x…dEaD`),
`extra = received * extraBps / 10000` to `extraRecipient`, the rest (incl. rounding dust) to `treasury`.

EIP-712 domain: name `ScanPayments`, version `1`, chainId, verifying contract (ERC-5267 `eip712Domain()`).

```
ScanRequest(address payer,string chain,string target,uint256 maxPrice,uint256 nonce,uint256 deadline)
PublishReport(uint256 scanId,string reportCid,bytes32 reportHash,uint8 score,uint8 verdict,bytes attestation,uint256 deadline)
FreeScanVoucher(address holder,string chain,string target,uint256 tierId,uint256 nonce,uint256 deadline)
```

Holder tiers `{minBalance, freeScansPerPeriod, discountBps}`, strictly increasing, max 10. Credit modes:
`0 OFF` · `1 ON_CHAIN_BALANCE` · `2 SIGNED_VOUCHER` · `3 BALANCE_AND_VOUCHER`. Periods are epoch-aligned
(default 1 day, resets 00:00 UTC). A report hook always gets exactly 2M gas, and a failing hook never blocks publishing.

</details>

## Security

Found a bug? Please report it privately, see [SECURITY.md](SECURITY.md). Do not open a public issue for vulnerabilities.

## License

[MIT](LICENSE) © BYTEJURY
