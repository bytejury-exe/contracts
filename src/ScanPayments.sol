// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {ScanRoles} from "./ScanRoles.sol";
import {HolderCredits} from "./HolderCredits.sol";
import {IReportHook} from "./interfaces/IReportHook.sol";

/// @title ScanPayments
/// @notice Pay-per-scan entry point of the scam scanner. Users pay `quote()` utility tokens per scan; the amount
///         actually received is split into a burned part (`burnBps`), an optional extra recipient (`extraBps`) and the
///         treasury (remainder, which also absorbs rounding dust). Utility-token holders can get free scans
///         (see HolderCredits). The oracle publishes the resulting report; the latest report per target is public.
/// @dev Not upgradeable by design. The contract never keeps balances between transactions: every payment is
///      forwarded in the same call. Report ids start at 1 (scanId 0 = "no report").
contract ScanPayments is HolderCredits, Pausable, ReentrancyGuard, Nonces {
    using SafeERC20 for IERC20;

    // ------------------------------------------------------------------ types

    struct Report {
        uint256 scanId;
        string reportCid;
        bytes32 reportHash;
        /// @dev Safety score 0-100, higher is safer.
        uint8 score;
        uint8 verdict;
        uint64 publishedAt;
    }

    struct ChainConfig {
        bool supported;
        /// @dev Price override for this chain; 0 = use `scanPrice`.
        uint256 price;
    }

    /// @notice EIP-712 message a payer signs for a gasless (relayed) paid scan.
    struct ScanRequest {
        address payer;
        string chain;
        string target;
        uint256 maxPrice;
        uint256 nonce;
        uint256 deadline;
    }

    /// @notice EIP-712 message the oracle signs so that any relayer can publish the report.
    struct PublishReport {
        uint256 scanId;
        string reportCid;
        bytes32 reportHash;
        /// @dev Safety score 0-100, higher is safer.
        uint8 score;
        uint8 verdict;
        bytes attestation;
        uint256 deadline;
    }

    /// @notice Optional EIP-2612 permit for the utility token (deadline 0 = no permit).
    struct PermitSig {
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /// @notice Every admin-tunable setting in one struct (read by the admin UI).
    struct Config {
        address utilityToken;
        address treasury;
        address oracle;
        address creditSigner;
        address extraRecipient;
        address reportHook;
        uint256 scanPrice;
        uint16 burnBps;
        uint16 extraBps;
        uint16 rescanPriceBps;
        uint32 rescanCooldown;
        CreditMode creditMode;
        uint32 creditPeriod;
        uint32 minHoldSeconds;
        bool manualCreditsFirst;
        uint8 pausedFeatures;
        bool paused;
        bool relayerAllowlistEnabled;
        uint256 nextScanId;
        uint256 totalBurned;
        uint256 totalToTreasury;
        uint256 totalToExtra;
    }

    // ------------------------------------------------------------------ constants

    address public constant DEAD = 0x000000000000000000000000000000000000dEaD;
    uint8 public constant MAX_VERDICT = 4;
    /// @notice Safety score range is 0-100, higher is safer.
    uint8 public constant MAX_SCORE = 100;
    uint256 public constant MAX_STRING_LENGTH = 128;
    uint16 public constant MAX_RESCAN_PRICE_BPS = 30_000;
    uint32 public constant MAX_RESCAN_COOLDOWN = 30 days;
    /// @notice Gas forwarded to the report hook on every publish.
    uint256 public constant HOOK_GAS = 2_000_000;

    uint8 public constant FEATURE_PAID_SCANS = 1;
    uint8 public constant FEATURE_FREE_SCANS = 2;
    uint8 public constant FEATURE_BY_SIG = 4;
    uint8 public constant FEATURE_PUBLISHING = 8;

    bytes32 public constant SCAN_REQUEST_TYPEHASH = keccak256(
        "ScanRequest(address payer,string chain,string target,uint256 maxPrice,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant PUBLISH_REPORT_TYPEHASH = keccak256(
        "PublishReport(uint256 scanId,string reportCid,bytes32 reportHash,uint8 score,uint8 verdict,bytes attestation,uint256 deadline)"
    );

    // ------------------------------------------------------------------ storage

    address public utilityToken;
    uint256 public scanPrice;
    address public treasury;
    uint16 public burnBps = 5_000;
    address public oracle;
    uint256 public nextScanId = 1;

    uint256 public totalBurned;
    uint256 public totalToTreasury;
    uint256 public totalToExtra;

    /// @notice Optional third split recipient (e.g. future staking / rewards pool).
    address public extraRecipient;
    uint16 public extraBps;

    /// @notice Price multiplier (bps) for targets that already have a report. 10000 = same price.
    uint16 public rescanPriceBps = BPS;
    /// @notice Minimum time between two scan requests for the same target.
    uint32 public rescanCooldown;

    /// @notice Bitmask of paused features (FEATURE_* constants), on top of the global pause.
    uint8 public pausedFeatures;
    /// @notice When enabled, signature-based entry points must be submitted by an allowlisted relayer.
    bool public relayerAllowlistEnabled;
    mapping(address relayer => bool) public isRelayer;

    /// @notice Optional add-on notified after each published report (ERC-7512 / ERC-8004 attestations).
    address public reportHook;

    mapping(string chain => ChainConfig) internal _chains;
    mapping(string chain => bool) internal _chainListed;
    string[] internal _chainList;

    /// @notice targetKey of every scan id.
    mapping(uint256 scanId => bytes32) public scanTarget;
    /// @notice Last request time per targetKey (re-scan cooldown).
    mapping(bytes32 targetKey => uint256) public lastRequestedAt;
    mapping(bytes32 targetKey => Report) internal _reports;
    /// @notice Oracle signatures already used with publishReportBySig.
    mapping(bytes32 digest => bool) public usedReportDigest;

    // ------------------------------------------------------------------ events

    event UtilityTokenChanged(address indexed oldToken, address indexed newToken);
    event ScanPriceChanged(uint256 oldPrice, uint256 newPrice);
    event TreasuryChanged(address indexed oldTreasury, address indexed newTreasury);
    event BurnBpsChanged(uint16 oldBps, uint16 newBps);
    event OracleChanged(address indexed oldOracle, address indexed newOracle);
    event ExtraSplitChanged(address indexed recipient, uint16 bps);
    event RescanPolicyChanged(uint16 priceBps, uint32 cooldown);
    event ChainConfigChanged(string chain, bool supported, uint256 price);
    event PausedFeaturesChanged(uint8 oldMask, uint8 newMask);
    event RelayerAllowlistToggled(bool enabled);
    event RelayerSet(address indexed relayer, bool allowed);
    event ReportHookChanged(address indexed oldHook, address indexed newHook);
    event TokensRescued(address indexed token, address indexed to, uint256 amount);

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
    event ExtraSplitPaid(uint256 indexed scanId, address indexed recipient, uint256 amount);
    event FreeScanUsed(uint256 indexed scanId, address indexed holder, CreditSource source, uint256 tierId);
    event ReportPublished(
        uint256 indexed scanId,
        bytes32 indexed targetKey,
        string reportCid,
        bytes32 reportHash,
        uint8 score,
        uint8 verdict
    );
    event ReportHookFailed(uint256 indexed scanId, bytes reason);

    // ------------------------------------------------------------------ errors

    error TokenNotSet();
    error InvalidBps();
    error InvalidAmount();
    error InvalidString();
    error NotAContract();
    error OnlyOracle();
    error FeaturePaused(uint8 feature);
    error UnsupportedChain(string chain);
    error RescanCooldownActive(uint256 availableAt);
    error PriceAboveMax(uint256 price, uint256 maxPrice);
    error SignatureExpired();
    error DigestUsed();
    error RelayerNotAllowed();
    error UnknownScan(uint256 scanId);
    error InvalidVerdict();
    error InvalidScore();
    error StaleReport(uint256 latestScanId);
    error InsufficientGasForHook();

    // ------------------------------------------------------------------ modifiers

    modifier onlyOracle() {
        if (msg.sender != oracle) revert OnlyOracle();
        _;
    }

    modifier whenFeature(uint8 feature) {
        _requireFeature(feature);
        _;
    }

    // ------------------------------------------------------------------ constructor

    /// @param initialOwner     Admin (Ownable2Step).
    /// @param initialTreasury  Receives the non-burned part of payments.
    /// @param initialToken     Utility token; may be address(0) until the token launches (paid scans revert).
    /// @param initialPrice     Default price per scan in token units (> 0).
    /// @param initialOracle    Backend key allowed to publish reports.
    /// @dev The deployment chain (`eip155:<block.chainid>`) is supported from the start.
    constructor(
        address initialOwner,
        address initialTreasury,
        address initialToken,
        uint256 initialPrice,
        address initialOracle
    ) ScanRoles(initialOwner) EIP712("ScanPayments", "1") {
        if (initialTreasury == address(0) || initialOracle == address(0)) revert ZeroAddress();
        if (initialPrice == 0) revert InvalidAmount();
        treasury = initialTreasury;
        utilityToken = initialToken;
        scanPrice = initialPrice;
        oracle = initialOracle;
        _setChainConfig(string.concat("eip155:", Strings.toString(block.chainid)), true, 0);
    }

    // ================================================================== user entry points

    /// @notice Pay for a scan of `target` on `chain` (CAIP-2). Approve exactly `quote(msg.sender, chain, target)` first.
    function requestScan(string calldata chain, string calldata target)
        external
        nonReentrant
        whenNotPaused
        returns (uint256 scanId)
    {
        return _paidScan(msg.sender, chain, target, type(uint256).max);
    }

    /// @notice Same as requestScan, but first applies an EIP-2612 permit for exactly the quoted price.
    /// @dev Permit is wrapped in try/catch so a front-run permit (already used) does not block the scan.
    function requestScanWithPermit(
        string calldata chain,
        string calldata target,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant whenNotPaused returns (uint256 scanId) {
        _tryPermit(msg.sender, quote(msg.sender, chain, target), PermitSig(deadline, v, r, s));
        return _paidScan(msg.sender, chain, target, type(uint256).max);
    }

    /// @notice Gasless paid scan: `req.payer` signs an EIP-712 ScanRequest (EOA or ERC-1271 wallet), anyone submits.
    /// @param permit Optional EIP-2612 permit for `req.maxPrice` (deadline 0 = skip, allowance must exist).
    function requestScanBySig(ScanRequest calldata req, bytes calldata signature, PermitSig calldata permit)
        external
        nonReentrant
        whenNotPaused
        whenFeature(FEATURE_BY_SIG)
        returns (uint256 scanId)
    {
        _checkRelayer(req.payer);
        if (block.timestamp > req.deadline) revert SignatureExpired();
        _useCheckedNonce(req.payer, req.nonce);
        if (!SignatureChecker.isValidSignatureNow(req.payer, _hashScanRequest(req), signature)) {
            revert InvalidSignature();
        }
        if (permit.deadline != 0) _tryPermit(req.payer, req.maxPrice, permit);
        return _paidScan(req.payer, req.chain, req.target, req.maxPrice);
    }

    /// @notice Free scan using manual credits or (ON_CHAIN_BALANCE mode) the caller's holder tier.
    function requestFreeScan(string calldata chain, string calldata target)
        external
        nonReentrant
        whenNotPaused
        whenFeature(FEATURE_FREE_SCANS)
        returns (uint256 scanId)
    {
        (CreditSource source, uint256 tierId) = _consumeFreeCredit(msg.sender);
        return _freeScan(msg.sender, chain, target, source, tierId);
    }

    /// @notice Free scan authorised by a backend-signed FreeScanVoucher (SIGNED_VOUCHER / BALANCE_AND_VOUCHER modes).
    /// @dev The holder can submit it, or any (allowlisted) relayer can submit it gaslessly on the holder's behalf.
    function requestFreeScanWithVoucher(FreeScanVoucher calldata voucher, bytes calldata signature)
        external
        nonReentrant
        whenNotPaused
        whenFeature(FEATURE_FREE_SCANS)
        returns (uint256 scanId)
    {
        if (msg.sender != voucher.holder) {
            _requireFeature(FEATURE_BY_SIG);
            _checkRelayer(voucher.holder);
        }
        _consumeVoucher(voucher, signature);
        return _freeScan(voucher.holder, voucher.chain, voucher.target, CreditSource.VOUCHER, voucher.tierId);
    }

    // ================================================================== oracle

    /// @notice Publish the report of `scanId`. It becomes the latest report of that scan's target.
    /// @param score Safety score 0-100, higher is safer.
    function publishReport(uint256 scanId, string calldata reportCid, bytes32 reportHash, uint8 score, uint8 verdict)
        external
        nonReentrant
        whenNotPaused
        whenFeature(FEATURE_PUBLISHING)
        onlyOracle
    {
        _publish(scanId, reportCid, reportHash, score, verdict, "");
    }

    /// @notice publishReport plus an `attestation` payload forwarded to the report hook (e.g. ERC-7512 summary).
    function publishReportWithAttestation(
        uint256 scanId,
        string calldata reportCid,
        bytes32 reportHash,
        uint8 score,
        uint8 verdict,
        bytes calldata attestation
    ) external nonReentrant whenNotPaused whenFeature(FEATURE_PUBLISHING) onlyOracle {
        _publish(scanId, reportCid, reportHash, score, verdict, attestation);
    }

    /// @notice Publish a report signed by the oracle (EOA or ERC-1271); any relayer may submit. Each signature works once.
    function publishReportBySig(PublishReport calldata report, bytes calldata signature)
        external
        nonReentrant
        whenNotPaused
        whenFeature(FEATURE_PUBLISHING)
        whenFeature(FEATURE_BY_SIG)
    {
        _checkRelayer(oracle);
        if (block.timestamp > report.deadline) revert SignatureExpired();
        bytes32 digest = _hashPublishReport(report);
        if (usedReportDigest[digest]) revert DigestUsed();
        if (!SignatureChecker.isValidSignatureNow(oracle, digest, signature)) revert InvalidSignature();
        usedReportDigest[digest] = true;
        _publish(report.scanId, report.reportCid, report.reportHash, report.score, report.verdict, report.attestation);
    }

    // ================================================================== admin (owner)

    /// @notice Switch the utility token. Only the new token is accepted afterwards.
    function setUtilityToken(address newToken) external onlyOwner {
        if (newToken == address(0)) revert ZeroAddress();
        if (newToken.code.length == 0) revert NotAContract();
        emit UtilityTokenChanged(utilityToken, newToken);
        utilityToken = newToken;
    }

    function setTreasury(address newTreasury) external onlyOwner {
        if (newTreasury == address(0)) revert ZeroAddress();
        emit TreasuryChanged(treasury, newTreasury);
        treasury = newTreasury;
    }

    /// @notice Burned share in bps; `newBps + extraBps` must not exceed 10000.
    function setBurnBps(uint16 newBps) external onlyOwner {
        if (uint256(newBps) + extraBps > BPS) revert InvalidBps();
        emit BurnBpsChanged(burnBps, newBps);
        burnBps = newBps;
    }

    /// @notice Optional extra split (recipient may be zero only when bps is zero).
    function setExtraSplit(address recipient, uint16 bps) external onlyOwner {
        if (uint256(bps) + burnBps > BPS) revert InvalidBps();
        if (bps != 0 && recipient == address(0)) revert ZeroAddress();
        extraRecipient = recipient;
        extraBps = bps;
        emit ExtraSplitChanged(recipient, bps);
    }

    function setOracle(address newOracle) external onlyOwner {
        if (newOracle == address(0)) revert ZeroAddress();
        emit OracleChanged(oracle, newOracle);
        oracle = newOracle;
    }

    /// @notice Report hook (address(0) disables it).
    function setReportHook(address newHook) external onlyOwner {
        if (newHook != address(0) && newHook.code.length == 0) revert NotAContract();
        emit ReportHookChanged(reportHook, newHook);
        reportHook = newHook;
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Recover tokens sent here by mistake. The contract holds no funds between transactions
    ///         (payments are forwarded atomically and this call is non-reentrant), so nothing in flight can be taken.
    function rescueTokens(address token, address to, uint256 amount) external nonReentrant onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        IERC20(token).safeTransfer(to, amount);
        emit TokensRescued(token, to, amount);
    }

    // ================================================================== admin (operator or owner)

    function setScanPrice(uint256 newPrice) external onlyOperator {
        if (newPrice == 0) revert InvalidAmount();
        emit ScanPriceChanged(scanPrice, newPrice);
        scanPrice = newPrice;
    }

    /// @notice Re-scan price multiplier (1..30000 bps of the normal price) and cooldown between requests per target.
    function setRescanPolicy(uint16 priceBps, uint32 cooldown) external onlyOperator {
        if (priceBps == 0 || priceBps > MAX_RESCAN_PRICE_BPS || cooldown > MAX_RESCAN_COOLDOWN) revert InvalidBps();
        rescanPriceBps = priceBps;
        rescanCooldown = cooldown;
        emit RescanPolicyChanged(priceBps, cooldown);
    }

    /// @notice Allow / disallow a CAIP-2 chain and set its price override (0 = default `scanPrice`).
    function setChainConfig(string calldata chain, bool supported, uint256 price) external onlyOperator {
        _setChainConfig(chain, supported, price);
    }

    /// @notice Set the paused-feature bitmask (FEATURE_* constants).
    function setPausedFeatures(uint8 mask) external onlyOperator {
        emit PausedFeaturesChanged(pausedFeatures, mask);
        pausedFeatures = mask;
    }

    function setRelayerAllowlistEnabled(bool enabled) external onlyOperator {
        relayerAllowlistEnabled = enabled;
        emit RelayerAllowlistToggled(enabled);
    }

    function setRelayer(address relayer, bool allowed) external onlyOperator {
        if (relayer == address(0)) revert ZeroAddress();
        isRelayer[relayer] = allowed;
        emit RelayerSet(relayer, allowed);
    }

    /// @notice Emergency stop of every user / oracle entry point. Operators can pause; only the owner can unpause.
    function pause() external onlyOperator {
        _pause();
    }

    // ================================================================== views

    /// @notice Key under which reports of (`chain`, `target`) are stored.
    function targetKey(string calldata chain, string calldata target) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(chain, ":", target));
    }

    /// @notice Latest report for a target (all zero if none). `score` is the safety score 0-100, higher is safer.
    function latestReport(string calldata chain, string calldata target)
        external
        view
        returns (
            uint256 scanId,
            string memory reportCid,
            bytes32 reportHash,
            uint8 score,
            uint8 verdict,
            uint64 publishedAt
        )
    {
        Report storage r = _reports[targetKey(chain, target)];
        return (r.scanId, r.reportCid, r.reportHash, r.score, r.verdict, r.publishedAt);
    }

    /// @notice Price `payer` pays for a scan right now (chain override, re-scan multiplier, holder discount).
    function quote(address payer, string calldata chain, string calldata target) public view returns (uint256 price) {
        price = _chains[chain].price;
        if (price == 0) price = scanPrice;
        if (_reports[targetKey(chain, target)].scanId != 0) price = price * rescanPriceBps / BPS;
        price -= price * _discountBps(payer) / BPS;
    }

    function chainConfig(string calldata chain) external view returns (ChainConfig memory) {
        return _chains[chain];
    }

    /// @notice Every chain ever configured, with its current config.
    function getChains() external view returns (string[] memory chains, ChainConfig[] memory configs) {
        chains = _chainList;
        configs = new ChainConfig[](chains.length);
        for (uint256 i; i < chains.length; ++i) {
            configs[i] = _chains[chains[i]];
        }
    }

    /// @notice All settings in one call.
    function getConfig() external view returns (Config memory c) {
        c.utilityToken = utilityToken;
        c.treasury = treasury;
        c.oracle = oracle;
        c.creditSigner = creditSigner;
        c.extraRecipient = extraRecipient;
        c.reportHook = reportHook;
        c.scanPrice = scanPrice;
        c.burnBps = burnBps;
        c.extraBps = extraBps;
        c.rescanPriceBps = rescanPriceBps;
        c.rescanCooldown = rescanCooldown;
        c.creditMode = creditMode;
        c.creditPeriod = creditPeriod;
        c.minHoldSeconds = minHoldSeconds;
        c.manualCreditsFirst = manualCreditsFirst;
        c.pausedFeatures = pausedFeatures;
        c.paused = paused();
        c.relayerAllowlistEnabled = relayerAllowlistEnabled;
        c.nextScanId = nextScanId;
        c.totalBurned = totalBurned;
        c.totalToTreasury = totalToTreasury;
        c.totalToExtra = totalToExtra;
    }

    /// @notice EIP-712 domain separator (domain: name "ScanPayments", version "1", chainId, this contract).
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    // ================================================================== internal

    function _creditToken() internal view override returns (address) {
        return utilityToken;
    }

    function _paidScan(address payer, string calldata chain, string calldata target, uint256 maxPrice)
        private
        returns (uint256 scanId)
    {
        _requireFeature(FEATURE_PAID_SCANS);
        address token = utilityToken;
        if (token == address(0)) revert TokenNotSet();
        uint256 price = quote(payer, chain, target);
        if (price > maxPrice) revert PriceAboveMax(price, maxPrice);
        scanId = _registerScan(chain, target);
        uint256 received = _pull(IERC20(token), payer, price);
        (uint256 burned, uint256 toTreasury) = _distribute(IERC20(token), scanId, received);
        emit ScanRequested(scanId, payer, scanTarget[scanId], chain, target, token, received, burned, toTreasury);
    }

    function _freeScan(
        address holder,
        string calldata chain,
        string calldata target,
        CreditSource source,
        uint256 tierId
    ) private returns (uint256 scanId) {
        scanId = _registerScan(chain, target);
        emit ScanRequested(scanId, holder, scanTarget[scanId], chain, target, utilityToken, 0, 0, 0);
        emit FreeScanUsed(scanId, holder, source, tierId);
    }

    /// @dev Validates the target, enforces the re-scan cooldown and assigns the next scan id.
    function _registerScan(string calldata chain, string calldata target) private returns (uint256 scanId) {
        if (!_chains[chain].supported) revert UnsupportedChain(chain);
        uint256 len = bytes(target).length;
        if (len == 0 || len > MAX_STRING_LENGTH) revert InvalidString();
        bytes32 key = targetKey(chain, target);
        uint256 availableAt = lastRequestedAt[key] + rescanCooldown;
        if (lastRequestedAt[key] != 0 && block.timestamp < availableAt) revert RescanCooldownActive(availableAt);
        lastRequestedAt[key] = block.timestamp;
        scanId = nextScanId++;
        scanTarget[scanId] = key;
    }

    /// @dev Pulls `amount` and returns what actually arrived (fee-on-transfer safe).
    function _pull(IERC20 token, address payer, uint256 amount) private returns (uint256 received) {
        if (amount == 0) return 0;
        uint256 balanceBefore = token.balanceOf(address(this));
        token.safeTransferFrom(payer, address(this), amount);
        received = token.balanceOf(address(this)) - balanceBefore;
    }

    /// @dev burn = received * burnBps, extra = received * extraBps (both rounded down), treasury = remainder.
    function _distribute(IERC20 token, uint256 scanId, uint256 received)
        private
        returns (uint256 burned, uint256 toTreasury)
    {
        burned = received * burnBps / BPS;
        uint256 toExtra = received * extraBps / BPS;
        toTreasury = received - burned - toExtra;
        totalBurned += burned;
        totalToTreasury += toTreasury;
        totalToExtra += toExtra;
        if (burned != 0) _burn(token, burned);
        if (toExtra != 0) {
            address recipient = extraRecipient;
            token.safeTransfer(recipient, toExtra);
            emit ExtraSplitPaid(scanId, recipient, toExtra);
        }
        if (toTreasury != 0) token.safeTransfer(treasury, toTreasury);
    }

    /// @dev Tries `burn(uint256)`; whatever the balance did not actually drop by is sent to the dead address.
    function _burn(IERC20 token, uint256 amount) private {
        uint256 balanceBefore = token.balanceOf(address(this));
        // Low-level call on purpose: tokens without burn(), or whose burn() reverts, fall back to the dead address.
        (bool ok,) = address(token).call(abi.encodeWithSignature("burn(uint256)", amount));
        uint256 burnedViaCall = 0;
        if (ok) {
            uint256 balanceAfter = token.balanceOf(address(this));
            if (balanceAfter < balanceBefore) burnedViaCall = balanceBefore - balanceAfter;
        }
        if (burnedViaCall < amount) token.safeTransfer(DEAD, amount - burnedViaCall);
    }

    function _tryPermit(address owner_, uint256 value, PermitSig memory p) private {
        address token = utilityToken;
        if (token == address(0)) revert TokenNotSet();
        // A failed permit is ignored: either the allowance already exists (e.g. front-run permit) or transferFrom fails.
        try IERC20Permit(token).permit(owner_, address(this), value, p.deadline, p.v, p.r, p.s) {} catch {}
    }

    function _publish(
        uint256 scanId,
        string calldata reportCid,
        bytes32 reportHash,
        uint8 score,
        uint8 verdict,
        bytes memory attestation
    ) private {
        if (scanId == 0 || scanId >= nextScanId) revert UnknownScan(scanId);
        if (verdict > MAX_VERDICT) revert InvalidVerdict();
        if (score > MAX_SCORE) revert InvalidScore();
        if (bytes(reportCid).length == 0 || bytes(reportCid).length > MAX_STRING_LENGTH) revert InvalidString();
        bytes32 key = scanTarget[scanId];
        Report storage r = _reports[key];
        if (scanId < r.scanId) revert StaleReport(r.scanId);
        r.scanId = scanId;
        r.reportCid = reportCid;
        r.reportHash = reportHash;
        r.score = score;
        r.verdict = verdict;
        r.publishedAt = uint64(block.timestamp);
        emit ReportPublished(scanId, key, reportCid, reportHash, score, verdict);

        address hook = reportHook;
        if (hook != address(0)) {
            // The hook always gets exactly HOOK_GAS, so a failure is deterministic (never caused by a too-low
            // gas limit) and eth_estimateGas returns a limit that covers the hook.
            if (gasleft() < HOOK_GAS + HOOK_GAS / 63 + 20_000) revert InsufficientGasForHook();
            try IReportHook(hook).onReportPublished{gas: HOOK_GAS}(
                scanId, key, reportCid, reportHash, score, verdict, attestation
            ) {}
            catch (bytes memory reason) {
                emit ReportHookFailed(scanId, reason);
            }
        }
    }

    function _setChainConfig(string memory chain, bool supported, uint256 price) private {
        uint256 len = bytes(chain).length;
        if (len == 0 || len > MAX_STRING_LENGTH) revert InvalidString();
        _chains[chain] = ChainConfig(supported, price);
        if (!_chainListed[chain]) {
            _chainListed[chain] = true;
            _chainList.push(chain);
        }
        emit ChainConfigChanged(chain, supported, price);
    }

    function _checkRelayer(address principal) private view {
        if (relayerAllowlistEnabled && msg.sender != principal && !isRelayer[msg.sender]) revert RelayerNotAllowed();
    }

    function _requireFeature(uint8 feature) private view {
        if (pausedFeatures & feature != 0) revert FeaturePaused(feature);
    }

    function _hashScanRequest(ScanRequest calldata req) private view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    SCAN_REQUEST_TYPEHASH,
                    req.payer,
                    keccak256(bytes(req.chain)),
                    keccak256(bytes(req.target)),
                    req.maxPrice,
                    req.nonce,
                    req.deadline
                )
            )
        );
    }

    function _hashPublishReport(PublishReport calldata p) private view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    PUBLISH_REPORT_TYPEHASH,
                    p.scanId,
                    keccak256(bytes(p.reportCid)),
                    p.reportHash,
                    p.score,
                    p.verdict,
                    keccak256(p.attestation),
                    p.deadline
                )
            )
        );
    }
}
