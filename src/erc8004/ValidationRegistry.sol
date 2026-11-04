// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IIdentityRegistry, IValidationRegistry} from "./IERC8004.sol";

/// @title ValidationRegistry
/// @notice Minimal, non-upgradeable ERC-8004 Validation Registry. Deploy it where no official one exists
///         (Robinhood Chain 4663 has the official Identity + Reputation registries but no Validation registry).
/// @dev Behaviour follows the spec and the erc-8004 reference implementation (v2.0.0). Deviation: the identity
///      registry is fixed in the constructor instead of an `initialize()` call, since this contract is not a proxy.
contract ValidationRegistry is IValidationRegistry {
    struct ValidationStatus {
        address validatorAddress;
        uint256 agentId;
        uint8 response;
        bytes32 responseHash;
        string tag;
        uint256 lastUpdate;
        bool hasResponse;
    }

    uint8 public constant MAX_RESPONSE = 100;

    address internal immutable _identityRegistry;
    mapping(bytes32 requestHash => ValidationStatus) internal _validations;
    mapping(uint256 agentId => bytes32[]) internal _agentValidations;
    mapping(address validator => bytes32[]) internal _validatorRequests;

    error ZeroAddress();
    error RequestExists();
    error UnknownRequest();
    error NotAuthorized();
    error NotValidator();
    error InvalidResponse();

    constructor(address identityRegistry_) {
        if (identityRegistry_ == address(0)) revert ZeroAddress();
        _identityRegistry = identityRegistry_;
    }

    function getIdentityRegistry() external view returns (address) {
        return _identityRegistry;
    }

    /// @notice Request validation of `agentId`'s work. Caller must own `agentId` or be an approved operator.
    function validationRequest(
        address validatorAddress,
        uint256 agentId,
        string calldata requestURI,
        bytes32 requestHash
    ) external {
        if (validatorAddress == address(0)) revert ZeroAddress();
        if (_validations[requestHash].validatorAddress != address(0)) revert RequestExists();
        IIdentityRegistry registry = IIdentityRegistry(_identityRegistry);
        address agentOwner = registry.ownerOf(agentId);
        if (
            msg.sender != agentOwner && !registry.isApprovedForAll(agentOwner, msg.sender)
                && registry.getApproved(agentId) != msg.sender
        ) revert NotAuthorized();

        ValidationStatus storage s = _validations[requestHash];
        s.validatorAddress = validatorAddress;
        s.agentId = agentId;
        s.lastUpdate = block.timestamp;
        _agentValidations[agentId].push(requestHash);
        _validatorRequests[validatorAddress].push(requestHash);
        emit ValidationRequest(validatorAddress, agentId, requestURI, requestHash);
    }

    /// @notice Respond (0..100) to a request; callable only by its validator, repeatedly (progressive states).
    function validationResponse(
        bytes32 requestHash,
        uint8 response,
        string calldata responseURI,
        bytes32 responseHash,
        string calldata tag
    ) external {
        ValidationStatus storage s = _validations[requestHash];
        if (s.validatorAddress == address(0)) revert UnknownRequest();
        if (msg.sender != s.validatorAddress) revert NotValidator();
        if (response > MAX_RESPONSE) revert InvalidResponse();
        s.response = response;
        s.responseHash = responseHash;
        s.tag = tag;
        s.lastUpdate = block.timestamp;
        s.hasResponse = true;
        emit ValidationResponse(s.validatorAddress, s.agentId, requestHash, response, responseURI, responseHash, tag);
    }

    function getValidationStatus(bytes32 requestHash)
        external
        view
        returns (
            address validatorAddress,
            uint256 agentId,
            uint8 response,
            bytes32 responseHash,
            string memory tag,
            uint256 lastUpdate
        )
    {
        ValidationStatus storage s = _validations[requestHash];
        if (s.validatorAddress == address(0)) revert UnknownRequest();
        return (s.validatorAddress, s.agentId, s.response, s.responseHash, s.tag, s.lastUpdate);
    }

    /// @notice Count and average of answered validations, optionally filtered by validators and tag.
    function getSummary(uint256 agentId, address[] calldata validatorAddresses, string calldata tag)
        external
        view
        returns (uint64 count, uint8 averageResponse)
    {
        bytes32[] storage hashes = _agentValidations[agentId];
        bytes32 tagHash = keccak256(bytes(tag));
        bool filterTag = bytes(tag).length != 0;
        uint256 total = 0;
        for (uint256 i; i < hashes.length; ++i) {
            ValidationStatus storage s = _validations[hashes[i]];
            if (!s.hasResponse) continue;
            if (filterTag && keccak256(bytes(s.tag)) != tagHash) continue;
            if (validatorAddresses.length != 0 && !_contains(validatorAddresses, s.validatorAddress)) continue;
            total += s.response;
            ++count;
        }
        if (count != 0) averageResponse = uint8(total / count);
    }

    function getAgentValidations(uint256 agentId) external view returns (bytes32[] memory) {
        return _agentValidations[agentId];
    }

    function getValidatorRequests(address validatorAddress) external view returns (bytes32[] memory) {
        return _validatorRequests[validatorAddress];
    }

    function _contains(address[] calldata list, address value) private pure returns (bool) {
        for (uint256 i; i < list.length; ++i) {
            if (list[i] == value) return true;
        }
        return false;
    }
}
