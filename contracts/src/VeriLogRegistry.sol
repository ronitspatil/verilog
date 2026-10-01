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
///
///      Agent signing keys: every event is signed in the agent process with an
///      Ed25519 key registered here by KEY_ADMIN_ROLE. keyId = keccak256(pubkey).
///      A key is valid for an epoch when validFrom <= anchor.timestamp and
///      (revokedAt == 0 || anchor.timestamp < revokedAt). The anchorer (the
///      daemon) must never hold KEY_ADMIN_ROLE or DEFAULT_ADMIN_ROLE, or a
///      compromised daemon host could register its own key and forge events;
///      the contract refuses to give one account both sides.
contract VeriLogRegistry is AccessControl {
    /// @notice Role allowed to anchor epochs.
    bytes32 public constant ANCHORER_ROLE = keccak256("ANCHORER_ROLE");

    /// @notice Role allowed to register and revoke agent signing keys.
    bytes32 public constant KEY_ADMIN_ROLE = keccak256("KEY_ADMIN_ROLE");

    /// @dev Two storage slots: pubkey | validFrom (8 bytes) + revokedAt (8 bytes).
    struct AgentKey {
        bytes32 pubkey;
        uint64 validFrom;
        uint64 revokedAt;
    }

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

    /// @notice agentId => keyId => registered Ed25519 key.
    mapping(bytes32 agentId => mapping(bytes32 keyId => AgentKey)) public agentKeys;

    event LogAnchored(
        bytes32 indexed agentId, uint256 indexed epochId, bytes32 merkleRoot, uint32 logCount, uint64 timestamp
    );

    event AgentKeyRegistered(bytes32 indexed agentId, bytes32 indexed keyId, bytes32 pubkey, uint64 validFrom);
    event AgentKeyRevoked(bytes32 indexed agentId, bytes32 indexed keyId, uint64 revokedAt);

    error ZeroAgentId();
    error ZeroMerkleRoot();
    error ZeroLogCount();
    error ZeroAddress();
    error EpochNotAnchored(bytes32 agentId, uint256 epochId);
    error ZeroPubkey();
    error KeyExists(bytes32 agentId, bytes32 keyId);
    error UnknownKey(bytes32 agentId, bytes32 keyId);
    error KeyAlreadyRevoked(bytes32 agentId, bytes32 keyId);
    error AnchorerCannotAdminister(address account);

    /// @param admin    Receives DEFAULT_ADMIN_ROLE and KEY_ADMIN_ROLE. In production
    ///                 this is a multisig; it must not be the daemon's signer.
    /// @param anchorer Initial holder of ANCHORER_ROLE (the daemon's signer).
    constructor(address admin, address anchorer) {
        if (admin == address(0) || anchorer == address(0)) revert ZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(KEY_ADMIN_ROLE, admin);
        _grantRole(ANCHORER_ROLE, anchorer);
    }

    /// @dev Keeps the anchorer and the administrators apart: an account can
    ///      never hold ANCHORER_ROLE together with KEY_ADMIN_ROLE or DEFAULT_ADMIN_ROLE.
    function _grantRole(bytes32 role, address account) internal override returns (bool) {
        if (role == ANCHORER_ROLE) {
            if (hasRole(KEY_ADMIN_ROLE, account) || hasRole(DEFAULT_ADMIN_ROLE, account)) {
                revert AnchorerCannotAdminister(account);
            }
        } else if (role == KEY_ADMIN_ROLE || role == DEFAULT_ADMIN_ROLE) {
            if (hasRole(ANCHORER_ROLE, account)) revert AnchorerCannotAdminister(account);
        }
        return super._grantRole(role, account);
    }

    /// @notice Register an agent's Ed25519 public key, valid from this block on.
    /// @return keyId keccak256(pubkey), the key_id carried by the agent's events.
    function registerAgentKey(bytes32 agentId, bytes32 pubkey)
        external
        onlyRole(KEY_ADMIN_ROLE)
        returns (bytes32 keyId)
    {
        if (agentId == bytes32(0)) revert ZeroAgentId();
        if (pubkey == bytes32(0)) revert ZeroPubkey();
        keyId = keccak256(abi.encodePacked(pubkey));
        if (agentKeys[agentId][keyId].pubkey != bytes32(0)) revert KeyExists(agentId, keyId);
        uint64 ts = uint64(block.timestamp);
        agentKeys[agentId][keyId] = AgentKey({pubkey: pubkey, validFrom: ts, revokedAt: 0});
        emit AgentKeyRegistered(agentId, keyId, pubkey, ts);
    }

    /// @notice Revoke an agent key. Epochs anchored from this block on no longer
    ///         accept its signatures; earlier epochs stay valid.
    function revokeAgentKey(bytes32 agentId, bytes32 keyId) external onlyRole(KEY_ADMIN_ROLE) {
        AgentKey storage k = agentKeys[agentId][keyId];
        if (k.pubkey == bytes32(0)) revert UnknownKey(agentId, keyId);
        if (k.revokedAt != 0) revert KeyAlreadyRevoked(agentId, keyId);
        uint64 ts = uint64(block.timestamp);
        k.revokedAt = ts;
        emit AgentKeyRevoked(agentId, keyId, ts);
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
