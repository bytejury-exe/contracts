// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/// @dev Plain ERC20 without burn().
contract MockERC20 is ERC20 {
    constructor() ERC20("Mock", "MOCK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev ERC20 with a working burn(uint256).
contract MockERC20Burnable is ERC20Burnable {
    constructor() ERC20("Burnable", "BURN") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev ERC20 + EIP-2612 permit + burn().
contract MockERC20Permit is ERC20Permit, ERC20Burnable {
    constructor() ERC20("Permit", "PRMT") ERC20Permit("Permit") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev Takes `feeBps` of every transfer (fee is destroyed). No burn().
contract FeeOnTransferToken is ERC20 {
    uint256 public immutable feeBps;

    constructor(uint256 feeBps_) ERC20("Fee", "FEE") {
        feeBps = feeBps_;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0)) {
            uint256 fee = value * feeBps / 10_000;
            super._update(from, address(0), fee);
            value -= fee;
        }
        super._update(from, to, value);
    }
}

/// @dev burn(uint256) always reverts.
contract RevertingBurnToken is ERC20 {
    constructor() ERC20("NoBurn", "NOBURN") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function burn(uint256) external pure {
        revert("burn disabled");
    }
}

/// @dev burn(uint256) succeeds but does nothing (balance must be verified by the caller).
contract NoopBurnToken is ERC20 {
    constructor() ERC20("Noop", "NOOP") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function burn(uint256) external {}
}
