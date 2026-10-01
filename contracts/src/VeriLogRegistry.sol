// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/// @title VeriLogRegistry
/// @notice Stores Merkle roots of AI agent audit-log epochs, keyed by agent and epoch.
/// @dev Hash scheme (shared with the off-chain daemon and verifier):
///      contentDigest = sha256(canonicalEventJson)
///      leaf          = keccak256(contentDigest)              (32-byte preimage)
///      node          = keccak256(min(a, b) || max(a, b))      (64-byte preimage, sorted pair)
///      An odd node at any level is promoted unchanged to the next level.
///      This is exactly the scheme OpenZeppelin's MerkleProof verifies, and the
///      differing preimage lengths domain-separate leaves from internal nodes.
///      agentId is keccak256(utf8(agentIdString)).
contract VeriLogRegistry is AccessControl {
    /// @notice Role allowed to anchor epochs.
    bytes32 public constant ANCHORER_ROLE = keccak256("ANCHORER_ROLE");

    /// @dev Packs into two storage slots: merkleRoot | timestamp (8 bytes) + logCount (4 bytes).
    struct Anchor {
        bytes32 merkleRoot;
        uint64 timestamp;
        uint32 logCount;
    }

    /// @notice agentId => epochId => anchor. Epochs start at 1.
    mapping(bytes32 => mapping(uint256 => Anchor)) public agentAnchors;

    /// @notice agentId => most recently anchored epoch (0 if none).
    mapping(bytes32 => uint256) public latestEpoch;

    event LogAnchored(
        bytes32 indexed agentId, uint256 indexed epochId, bytes32 merkleRoot, uint32 logCount, uint64 timestamp
    );

    error ZeroAgentId();
    error ZeroMerkleRoot();
    error ZeroLogCount();
    error ZeroAddress();
    error EpochNotAnchored(bytes32 agentId, uint256 epochId);

    /// @param admin   Receives DEFAULT_ADMIN_ROLE (can grant and revoke ANCHORER_ROLE).
    /// @param anchorer Initial holder of ANCHORER_ROLE (the daemon's signer).
    constructor(address admin, address anchorer) {
        if (admin == address(0) || anchorer == address(0)) revert ZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ANCHORER_ROLE, anchorer);
    }

    /// @notice Anchor the Merkle root of the next epoch for `agentId`.
    /// @return epochId The epoch number assigned to this anchor.
    function anchorEpoch(bytes32 agentId, bytes32 merkleRoot, uint32 logCount)
        external
        onlyRole(ANCHORER_ROLE)
        returns (uint256 epochId)
    {
        if (agentId == bytes32(0)) revert ZeroAgentId();
        if (merkleRoot == bytes32(0)) revert ZeroMerkleRoot();
        if (logCount == 0) revert ZeroLogCount();

        unchecked {
            // Cannot overflow: one increment per transaction.
            epochId = latestEpoch[agentId] + 1;
        }
        latestEpoch[agentId] = epochId;

        uint64 ts = uint64(block.timestamp);
        agentAnchors[agentId][epochId] = Anchor({merkleRoot: merkleRoot, timestamp: ts, logCount: logCount});

        emit LogAnchored(agentId, epochId, merkleRoot, logCount, ts);
    }

    /// @notice Verify that `leaf` is included in the tree with root `root`.
    function verifyProof(bytes32 leaf, bytes32[] calldata proof, bytes32 root) external pure returns (bool) {
        return MerkleProof.verifyCalldata(proof, root, leaf);
    }

    /// @notice Verify that `leaf` is included in the anchored epoch `epochId` of `agentId`.
    /// @dev Reverts with EpochNotAnchored if the epoch has no anchor, so callers can tell
    ///      "not anchored" apart from "not included".
    function verifyAnchoredLeaf(bytes32 agentId, uint256 epochId, bytes32 leaf, bytes32[] calldata proof)
        external
        view
        returns (bool)
    {
        bytes32 root = agentAnchors[agentId][epochId].merkleRoot;
        if (root == bytes32(0)) revert EpochNotAnchored(agentId, epochId);
        return MerkleProof.verifyCalldata(proof, root, leaf);
    }
}
