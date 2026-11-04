// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {ScanRoles} from "./ScanRoles.sol";

/// @title HolderCredits
/// @notice Free-scan accounting for utility-token holders plus manual (promo) credits.
///
/// Tier credits: holders of at least `minBalance` utility tokens get `freeScansPerPeriod` free scans per
/// `creditPeriod` and `discountBps` off paid scans. Tiers are sorted by strictly increasing `minBalance`;
/// the highest tier reached applies. Tier ids are 1-based (0 = no tier).
///
/// Credit modes (anti-sybil):
///  - OFF:                 no tier credits, no discounts (manual credits still work);
///  - ON_CHAIN_BALANCE:    tier from `balanceOf(holder)` at request time (simple, can be farmed by moving tokens);
///  - SIGNED_VOUCHER:      backend checks holding duration (`minHoldSeconds`, enforced off-chain) and signs an
///                         EIP-712 `FreeScanVoucher` with `creditSigner`; per-period caps are enforced on-chain;
///  - BALANCE_AND_VOUCHER: voucher AND on-chain `balanceOf(holder) >= tier.minBalance`.
///
/// Manual credits (granted by the owner / a credit manager) are consumed before tier credits when
/// `manualCreditsFirst` is true (default), otherwise after. Voucher scans always consume tier credits.
abstract contract HolderCredits is ScanRoles, EIP712 {
    enum CreditMode {
        OFF,
        ON_CHAIN_BALANCE,
        SIGNED_VOUCHER,
        BALANCE_AND_VOUCHER
    }

    enum CreditSource {
        TIER,
        MANUAL,
        VOUCHER
    }

    struct Tier {
        uint256 minBalance;
        uint32 freeScansPerPeriod;
        uint16 discountBps;
    }

    struct FreeScanVoucher {
        address holder;
        string chain;
        string target;
        uint256 tierId;
        uint256 nonce;
        uint256 deadline;
    }

    struct Usage {
        uint64 periodIndex;
        uint32 used;
    }

    bytes32 public constant FREE_SCAN_VOUCHER_TYPEHASH = keccak256(
        "FreeScanVoucher(address holder,string chain,string target,uint256 tierId,uint256 nonce,uint256 deadline)"
    );
    uint256 public constant MAX_TIERS = 10;
    uint32 public constant MIN_CREDIT_PERIOD = 1 hours;
    uint32 public constant MAX_CREDIT_PERIOD = 365 days;
    uint16 internal constant BPS = 10_000;

    Tier[] internal _tiers;
    CreditMode public creditMode;
    uint32 public creditPeriod = 1 days;
    /// @notice Minimum holding time the backend requires before signing vouchers (config only, enforced off-chain).
    uint32 public minHoldSeconds;
    bool public manualCreditsFirst = true;
    /// @notice Backend key that signs FreeScanVouchers (EOA or ERC-1271 contract).
    address public creditSigner;

    mapping(address holder => uint256) public manualCredits;
    mapping(address holder => Usage) public usage;
    mapping(address holder => mapping(uint256 nonce => bool)) public voucherNonceUsed;

    event TiersUpdated(Tier[] tiers);
    event CreditConfigChanged(CreditMode mode, uint32 period, uint32 minHoldSeconds, bool manualCreditsFirst);
    event CreditSignerChanged(address indexed oldSigner, address indexed newSigner);
    event CreditsGranted(address indexed holder, uint256 amount, uint256 newBalance);
    event CreditsRevoked(address indexed holder, uint256 amount, uint256 newBalance);

    error InvalidTiers();
    error InvalidCreditConfig();
    error LengthMismatch();
    error NoFreeScansLeft();
    error InvalidTier(uint256 tierId);
    error VoucherModeDisabled();
    error VoucherExpired();
    error VoucherNonceUsed();
    error InvalidSignature();
    error BalanceTooLow();

    // ------------------------------------------------------------------ admin

    /// @notice Replace the whole tier table (add / update / remove in one call). Empty array removes all tiers.
    function setTiers(Tier[] calldata newTiers) external onlyOperator {
        if (newTiers.length > MAX_TIERS) revert InvalidTiers();
        delete _tiers;
        uint256 prevMin = 0;
        for (uint256 i; i < newTiers.length; ++i) {
            Tier calldata t = newTiers[i];
            if (t.minBalance <= prevMin || t.discountBps > BPS) revert InvalidTiers();
            prevMin = t.minBalance;
            _tiers.push(t);
        }
        emit TiersUpdated(newTiers);
    }

    /// @notice Credit mode, period length (seconds), required holding time (off-chain) and manual-credit order.
    /// @dev Periods are epoch-aligned (`block.timestamp / period`). Changing `period` re-buckets usage counters
    ///      (they effectively reset). Mode != OFF requires at least one tier.
    function setCreditConfig(CreditMode mode, uint32 period, uint32 minHold, bool manualFirst) external onlyOperator {
        if (period < MIN_CREDIT_PERIOD || period > MAX_CREDIT_PERIOD || minHold > MAX_CREDIT_PERIOD) {
            revert InvalidCreditConfig();
        }
        if (mode != CreditMode.OFF && _tiers.length == 0) revert InvalidCreditConfig();
        creditMode = mode;
        creditPeriod = period;
        minHoldSeconds = minHold;
        manualCreditsFirst = manualFirst;
        emit CreditConfigChanged(mode, period, minHold, manualFirst);
    }

    /// @notice Key that signs FreeScanVouchers.
    function setCreditSigner(address newSigner) external onlyOwner {
        if (newSigner == address(0)) revert ZeroAddress();
        emit CreditSignerChanged(creditSigner, newSigner);
        creditSigner = newSigner;
    }

    /// @notice Add manual free-scan credits (promos, partners, KOLs).
    function grantCredits(address[] calldata holders, uint256[] calldata amounts) external onlyCreditManager {
        if (holders.length != amounts.length) revert LengthMismatch();
        for (uint256 i; i < holders.length; ++i) {
            if (holders[i] == address(0)) revert ZeroAddress();
            uint256 balance = manualCredits[holders[i]] + amounts[i];
            manualCredits[holders[i]] = balance;
            emit CreditsGranted(holders[i], amounts[i], balance);
        }
    }

    /// @notice Remove manual credits (clamped at zero).
    function revokeCredits(address[] calldata holders, uint256[] calldata amounts) external onlyCreditManager {
        if (holders.length != amounts.length) revert LengthMismatch();
        for (uint256 i; i < holders.length; ++i) {
            uint256 current = manualCredits[holders[i]];
            uint256 removed = amounts[i] > current ? current : amounts[i];
            manualCredits[holders[i]] = current - removed;
            emit CreditsRevoked(holders[i], removed, current - removed);
        }
    }

    // ------------------------------------------------------------------ views

    function getTiers() external view returns (Tier[] memory) {
        return _tiers;
    }

    /// @notice Highest tier reached by `holder`'s current utility-token balance (1-based, 0 = none).
    function tierOf(address holder) public view returns (uint256 tierId) {
        address token = _creditToken();
        uint256 n = _tiers.length;
        if (token == address(0) || n == 0) return 0;
        uint256 balance = IERC20(token).balanceOf(holder);
        for (uint256 i = n; i > 0; --i) {
            if (balance >= _tiers[i - 1].minBalance) return i;
        }
        return 0;
    }

    /// @notice Free scans `holder` can use right now: manual credits + remaining balance-tier credits.
    /// @dev In voucher modes the tier part is an estimate; the backend decides which tier it vouches for.
    function freeScansLeft(address holder) external view returns (uint256) {
        uint256 left = manualCredits[holder];
        if (creditMode != CreditMode.OFF) {
            uint256 tierId = tierOf(holder);
            if (tierId != 0) left += _tierCreditsLeft(holder, tierId);
        }
        return left;
    }

    /// @notice Current period bucket. Epoch-aligned: with a 1-day period every bucket starts at 00:00 UTC.
    function currentPeriod() public view returns (uint64) {
        return uint64(block.timestamp / creditPeriod);
    }

    // ------------------------------------------------------------------ internal

    /// @dev Utility token used for balance checks.
    function _creditToken() internal view virtual returns (address);

    /// @dev Consume one credit for a plain (non-voucher) free scan.
    function _consumeFreeCredit(address holder) internal returns (CreditSource, uint256 tierId) {
        if (manualCreditsFirst && _useManual(holder)) return (CreditSource.MANUAL, 0);
        if (creditMode == CreditMode.ON_CHAIN_BALANCE) {
            tierId = tierOf(holder);
            if (tierId != 0 && _tierCreditsLeft(holder, tierId) != 0) {
                _useTier(holder);
                return (CreditSource.TIER, tierId);
            }
        }
        if (!manualCreditsFirst && _useManual(holder)) return (CreditSource.MANUAL, 0);
        revert NoFreeScansLeft();
    }

    /// @dev Verify a backend-signed voucher and consume one tier credit for `voucher.holder`.
    function _consumeVoucher(FreeScanVoucher calldata voucher, bytes calldata signature) internal {
        CreditMode mode = creditMode;
        if (mode != CreditMode.SIGNED_VOUCHER && mode != CreditMode.BALANCE_AND_VOUCHER) revert VoucherModeDisabled();
        if (block.timestamp > voucher.deadline) revert VoucherExpired();
        if (voucher.tierId == 0 || voucher.tierId > _tiers.length) revert InvalidTier(voucher.tierId);
        if (voucherNonceUsed[voucher.holder][voucher.nonce]) revert VoucherNonceUsed();
        if (!SignatureChecker.isValidSignatureNow(creditSigner, _hashVoucher(voucher), signature)) {
            revert InvalidSignature();
        }
        if (mode == CreditMode.BALANCE_AND_VOUCHER) {
            address token = _creditToken();
            if (token == address(0) || IERC20(token).balanceOf(voucher.holder) < _tiers[voucher.tierId - 1].minBalance)
            {
                revert BalanceTooLow();
            }
        }
        if (_tierCreditsLeft(voucher.holder, voucher.tierId) == 0) revert NoFreeScansLeft();
        voucherNonceUsed[voucher.holder][voucher.nonce] = true;
        _useTier(voucher.holder);
    }

    function _hashVoucher(FreeScanVoucher calldata v) internal view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    FREE_SCAN_VOUCHER_TYPEHASH,
                    v.holder,
                    keccak256(bytes(v.chain)),
                    keccak256(bytes(v.target)),
                    v.tierId,
                    v.nonce,
                    v.deadline
                )
            )
        );
    }

    /// @dev Discount (bps) for a paid scan by `payer`; 0 when credit mode is OFF.
    function _discountBps(address payer) internal view returns (uint256) {
        if (creditMode == CreditMode.OFF) return 0;
        uint256 tierId = tierOf(payer);
        return tierId == 0 ? 0 : _tiers[tierId - 1].discountBps;
    }

    function _tierCreditsLeft(address holder, uint256 tierId) private view returns (uint256) {
        uint256 cap = _tiers[tierId - 1].freeScansPerPeriod;
        Usage memory u = usage[holder];
        uint256 used = u.periodIndex == currentPeriod() ? u.used : 0;
        return cap > used ? cap - used : 0;
    }

    function _useTier(address holder) private {
        uint64 period = currentPeriod();
        Usage storage u = usage[holder];
        if (u.periodIndex != period) {
            u.periodIndex = period;
            u.used = 1;
        } else {
            ++u.used;
        }
    }

    function _useManual(address holder) private returns (bool) {
        uint256 credits = manualCredits[holder];
        if (credits == 0) return false;
        manualCredits[holder] = credits - 1;
        return true;
    }
}
