// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @title ScanRoles
/// @notice Owner (two-step transfer) is the super-admin and can do everything. Two optional day-to-day roles:
///         - operator:       prices, chains, tiers, credit settings, feature flags, relayers, emergency pause;
///         - credit manager: grant / revoke manual free-scan credits.
/// @dev Renouncing ownership is disabled: the contract always needs an admin to rotate keys and settings.
abstract contract ScanRoles is Ownable2Step {
    /// @notice Accounts allowed to change operational settings.
    mapping(address account => bool) public isOperator;
    /// @notice Accounts allowed to grant / revoke manual credits.
    mapping(address account => bool) public isCreditManager;

    event OperatorSet(address indexed account, bool enabled);
    event CreditManagerSet(address indexed account, bool enabled);

    error Unauthorized();
    error ZeroAddress();
    error RenounceDisabled();

    modifier onlyOperator() {
        if (msg.sender != owner() && !isOperator[msg.sender]) revert Unauthorized();
        _;
    }

    modifier onlyCreditManager() {
        if (msg.sender != owner() && !isCreditManager[msg.sender]) revert Unauthorized();
        _;
    }

    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @notice Grant or revoke the operator role.
    function setOperator(address account, bool enabled) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        isOperator[account] = enabled;
        emit OperatorSet(account, enabled);
    }

    /// @notice Grant or revoke the credit-manager role.
    function setCreditManager(address account, bool enabled) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        isCreditManager[account] = enabled;
        emit CreditManagerSet(account, enabled);
    }

    /// @notice Disabled. Use the two-step `transferOwnership` / `acceptOwnership` instead.
    function renounceOwnership() public pure override {
        revert RenounceDisabled();
    }
}
