// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, stdJson} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {VeriLogRegistry} from "../src/VeriLogRegistry.sol";
import {Deploy} from "../script/Deploy.s.sol";

contract VeriLogRegistryTest is Test {
    using stdJson for string;

    event LogAnchored(
        bytes32 indexed agentId, uint256 indexed epochId, bytes32 merkleRoot, uint32 logCount, uint64 timestamp
    );

    event AgentKeyRegistered(bytes32 indexed agentId, bytes32 indexed keyId, bytes32 pubkey, uint64 validFrom);
    event AgentKeyRevoked(bytes32 indexed agentId, bytes32 indexed keyId, uint64 revokedAt);

    VeriLogRegistry internal registry;
    address internal admin = makeAddr("admin");
    address internal anchorer = makeAddr("anchorer");
    address internal stranger = makeAddr("stranger");

    bytes32 internal constant AGENT = keccak256("agent-alpha");
    bytes32 internal constant ROOT = keccak256("root");
    bytes32 internal constant PUBKEY = keccak256("an ed25519 public key");

    function setUp() public {
        registry = new VeriLogRegistry(admin, anchorer);
    }

    // ----------------------------------------------------------------- deploy

    function test_ConstructorGrantsRoles() public view {
        assertTrue(registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(registry.hasRole(registry.KEY_ADMIN_ROLE(), admin));
        assertTrue(registry.hasRole(registry.ANCHORER_ROLE(), anchorer));
        assertFalse(registry.hasRole(registry.ANCHORER_ROLE(), admin));
        assertFalse(registry.hasRole(registry.KEY_ADMIN_ROLE(), anchorer));
        assertFalse(registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), anchorer));
    }

    function test_ConstructorRejectsAdminAsAnchorer() public {
        vm.expectRevert(abi.encodeWithSelector(VeriLogRegistry.AnchorerCannotAdminister.selector, admin));
        new VeriLogRegistry(admin, admin);
    }

    function test_ConstructorRejectsZeroAddress() public {
        vm.expectRevert(VeriLogRegistry.ZeroAddress.selector);
        new VeriLogRegistry(address(0), anchorer);
        vm.expectRevert(VeriLogRegistry.ZeroAddress.selector);
        new VeriLogRegistry(admin, address(0));
    }

    // ----------------------------------------------------------- access control

    function test_AnchorRequiresRole() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, registry.ANCHORER_ROLE()
            )
        );
        vm.prank(stranger);
        registry.anchorEpoch(AGENT, ROOT, 1);
    }

    function test_AdminCanGrantAndRevokeAnchorer() public {
        bytes32 role = registry.ANCHORER_ROLE();
        vm.prank(admin);
        registry.grantRole(role, stranger);
        vm.prank(stranger);
        assertEq(registry.anchorEpoch(AGENT, ROOT, 1), 1);

        vm.prank(admin);
        registry.revokeRole(role, stranger);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, role)
        );
        vm.prank(stranger);
        registry.anchorEpoch(AGENT, ROOT, 1);
    }

    function test_AnchorerCannotGrantRoles() public {
        bytes32 role = registry.ANCHORER_ROLE();
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, anchorer, registry.DEFAULT_ADMIN_ROLE()
            )
        );
        vm.prank(anchorer);
        registry.grantRole(role, stranger);
    }

    // -------------------------------------------------------------- agent keys

    function test_KeyAdminRegistersKey() public {
        vm.warp(1_800_000_000);
        bytes32 keyId = keccak256(abi.encodePacked(PUBKEY));
        vm.expectEmit(true, true, false, true, address(registry));
        emit AgentKeyRegistered(AGENT, keyId, PUBKEY, 1_800_000_000);
        vm.prank(admin);
        assertEq(registry.registerAgentKey(AGENT, PUBKEY), keyId);
        (bytes32 pub, uint64 validFrom, uint64 revokedAt) = registry.agentKeys(AGENT, keyId);
        assertEq(pub, PUBKEY);
        assertEq(validFrom, 1_800_000_000);
        assertEq(revokedAt, 0);
        // Keys are per agent.
        (pub,,) = registry.agentKeys(keccak256("agent-beta"), keyId);
        assertEq(pub, bytes32(0));
    }

    function test_KeyAdminRevokesKey() public {
        vm.warp(1_800_000_000);
        vm.prank(admin);
        bytes32 keyId = registry.registerAgentKey(AGENT, PUBKEY);
        vm.warp(1_800_000_500);
        vm.expectEmit(true, true, false, true, address(registry));
        emit AgentKeyRevoked(AGENT, keyId, 1_800_000_500);
        vm.prank(admin);
        registry.revokeAgentKey(AGENT, keyId);
        (bytes32 pub, uint64 validFrom, uint64 revokedAt) = registry.agentKeys(AGENT, keyId);
        assertEq(pub, PUBKEY);
        assertEq(validFrom, 1_800_000_000);
        assertEq(revokedAt, 1_800_000_500);
    }

    function test_AnchorerCannotRegisterOrRevokeKeys() public {
        bytes32 role = registry.KEY_ADMIN_ROLE();
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, anchorer, role)
        );
        vm.prank(anchorer);
        registry.registerAgentKey(AGENT, PUBKEY);

        vm.prank(admin);
        bytes32 keyId = registry.registerAgentKey(AGENT, PUBKEY);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, anchorer, role)
        );
        vm.prank(anchorer);
        registry.revokeAgentKey(AGENT, keyId);
    }

    function test_StrangerCannotRegisterKeys() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, registry.KEY_ADMIN_ROLE()
            )
        );
        vm.prank(stranger);
        registry.registerAgentKey(AGENT, PUBKEY);
    }

    function test_AnchorerCanNeverHoldAdminRoles() public {
        bytes32 keyAdmin = registry.KEY_ADMIN_ROLE();
        bytes32 defaultAdmin = registry.DEFAULT_ADMIN_ROLE();
        bytes32 anchorerRole = registry.ANCHORER_ROLE();
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(VeriLogRegistry.AnchorerCannotAdminister.selector, anchorer));
        registry.grantRole(keyAdmin, anchorer);
        vm.expectRevert(abi.encodeWithSelector(VeriLogRegistry.AnchorerCannotAdminister.selector, anchorer));
        registry.grantRole(defaultAdmin, anchorer);
        // ...and the reverse: a key admin cannot be made an anchorer.
        vm.expectRevert(abi.encodeWithSelector(VeriLogRegistry.AnchorerCannotAdminister.selector, admin));
        registry.grantRole(anchorerRole, admin);
        vm.stopPrank();
        assertFalse(registry.hasRole(keyAdmin, anchorer));
    }

    function test_KeyAdminRoleCanBeHandedOff() public {
        // The production hand-off: grant both admin roles to the multisig,
        // then the deployer renounces its own.
        address multisig = makeAddr("safe");
        bytes32 keyAdmin = registry.KEY_ADMIN_ROLE();
        bytes32 defaultAdmin = registry.DEFAULT_ADMIN_ROLE();
        vm.startPrank(admin);
        registry.grantRole(keyAdmin, multisig);
        registry.grantRole(defaultAdmin, multisig);
        registry.renounceRole(keyAdmin, admin);
        registry.renounceRole(defaultAdmin, admin);
        vm.stopPrank();

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, admin, keyAdmin)
        );
        vm.prank(admin);
        registry.registerAgentKey(AGENT, PUBKEY);
        vm.prank(multisig);
        registry.registerAgentKey(AGENT, PUBKEY);
    }

    function test_RegisterKeyErrors() public {
        vm.startPrank(admin);
        vm.expectRevert(VeriLogRegistry.ZeroAgentId.selector);
        registry.registerAgentKey(bytes32(0), PUBKEY);
        vm.expectRevert(VeriLogRegistry.ZeroPubkey.selector);
        registry.registerAgentKey(AGENT, bytes32(0));
        bytes32 keyId = registry.registerAgentKey(AGENT, PUBKEY);
        vm.expectRevert(abi.encodeWithSelector(VeriLogRegistry.KeyExists.selector, AGENT, keyId));
        registry.registerAgentKey(AGENT, PUBKEY);
        // A revoked key cannot be registered again.
        registry.revokeAgentKey(AGENT, keyId);
        vm.expectRevert(abi.encodeWithSelector(VeriLogRegistry.KeyExists.selector, AGENT, keyId));
        registry.registerAgentKey(AGENT, PUBKEY);
        vm.stopPrank();
    }

    function test_RevokeKeyErrors() public {
        bytes32 unknown = keccak256("nope");
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(VeriLogRegistry.UnknownKey.selector, AGENT, unknown));
        registry.revokeAgentKey(AGENT, unknown);
        bytes32 keyId = registry.registerAgentKey(AGENT, PUBKEY);
        registry.revokeAgentKey(AGENT, keyId);
        vm.expectRevert(abi.encodeWithSelector(VeriLogRegistry.KeyAlreadyRevoked.selector, AGENT, keyId));
        registry.revokeAgentKey(AGENT, keyId);
        vm.stopPrank();
    }

    function test_AgentKeyStructUsesTwoSlots() public {
        vm.warp(1_800_000_000);
        vm.prank(admin);
        bytes32 keyId = registry.registerAgentKey(AGENT, PUBKEY);
        // agentKeys is storage slot 3 (after _roles, agentAnchors and latestEpoch).
        bytes32 outer = keccak256(abi.encode(AGENT, uint256(3)));
        bytes32 base = keccak256(abi.encode(keyId, outer));
        assertEq(vm.load(address(registry), base), PUBKEY);
        assertEq(uint64(uint256(vm.load(address(registry), bytes32(uint256(base) + 1)))), 1_800_000_000);
    }

    function testFuzz_KeyIdIsKeccakOfPubkey(bytes32 agent, bytes32 pubkey, uint64 ts) public {
        vm.assume(agent != bytes32(0) && pubkey != bytes32(0) && ts != 0);
        vm.warp(ts);
        vm.prank(admin);
        bytes32 keyId = registry.registerAgentKey(agent, pubkey);
        assertEq(keyId, keccak256(abi.encodePacked(pubkey)));
        (bytes32 stored, uint64 validFrom, uint64 revokedAt) = registry.agentKeys(agent, keyId);
        assertEq(stored, pubkey);
        assertEq(validFrom, ts);
        assertEq(revokedAt, 0);
        // A different key id under the same agent is unknown.
        bytes32 other = keccak256(abi.encodePacked(keyId));
        (stored,,) = registry.agentKeys(agent, other);
        assertEq(stored, bytes32(0));
    }

    /// The key_id in the Go-generated signed vectors is keccak256 of the public key,
    /// which is exactly what registerAgentKey returns.
    function test_GoSignedVectorsKeyId() public {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/../testdata/signed_vectors.json"));
        bytes32 pubkey = json.readBytes32(".public_key");
        bytes32 keyId = json.readBytes32(".key_id");
        vm.prank(admin);
        assertEq(registry.registerAgentKey(keccak256(bytes(json.readString(".run[0].agent_id"))), pubkey), keyId);
        assertEq(json.readBytes32(".run[0].key_id"), keyId);
    }

    // ------------------------------------------------------------------ deploy script

    function test_DeployScriptKeepsAnchorerOutOfKeyAdmin() public {
        Deploy script = new Deploy();
        vm.setEnv("VERILOG_ADMIN", vm.toString(admin));
        vm.setEnv("VERILOG_ANCHORER", vm.toString(anchorer));
        VeriLogRegistry deployed = script.run();
        assertTrue(deployed.hasRole(deployed.KEY_ADMIN_ROLE(), admin));
        assertTrue(deployed.hasRole(deployed.ANCHORER_ROLE(), anchorer));
        assertFalse(deployed.hasRole(deployed.KEY_ADMIN_ROLE(), anchorer));
        assertFalse(deployed.hasRole(deployed.DEFAULT_ADMIN_ROLE(), anchorer));

        vm.setEnv("VERILOG_ANCHORER", vm.toString(admin));
        vm.expectRevert(bytes("VERILOG_ANCHORER must differ from the admin (the anchorer never holds KEY_ADMIN_ROLE)"));
        script.run();
    }

    // ---------------------------------------------------------------- anchoring

    function test_AnchorStoresAndIncrementsEpoch() public {
        vm.warp(1_800_000_000);
        vm.startPrank(anchorer);
        assertEq(registry.anchorEpoch(AGENT, ROOT, 10), 1);
        assertEq(registry.anchorEpoch(AGENT, keccak256("root2"), 20), 2);
        vm.stopPrank();

        assertEq(registry.latestEpoch(AGENT), 2);
        (bytes32 root, uint64 ts, uint32 count) = registry.agentAnchors(AGENT, 1);
        assertEq(root, ROOT);
        assertEq(ts, 1_800_000_000);
        assertEq(count, 10);
        (root,, count) = registry.agentAnchors(AGENT, 2);
        assertEq(root, keccak256("root2"));
        assertEq(count, 20);
        (root,,) = registry.agentAnchors(AGENT, 3);
        assertEq(root, bytes32(0));
    }

    function test_EpochsAreIndependentPerAgent() public {
        bytes32 other = keccak256("agent-beta");
        vm.startPrank(anchorer);
        registry.anchorEpoch(AGENT, ROOT, 1);
        registry.anchorEpoch(AGENT, ROOT, 1);
        assertEq(registry.anchorEpoch(other, ROOT, 1), 1);
        vm.stopPrank();
        assertEq(registry.latestEpoch(AGENT), 2);
        assertEq(registry.latestEpoch(other), 1);
    }

    function test_AnchorEmitsEvent() public {
        vm.warp(1_800_000_123);
        vm.expectEmit(true, true, false, true, address(registry));
        emit LogAnchored(AGENT, 1, ROOT, 42, 1_800_000_123);
        vm.prank(anchorer);
        registry.anchorEpoch(AGENT, ROOT, 42);
    }

    function test_AnchorRejectsZeroValues() public {
        vm.startPrank(anchorer);
        vm.expectRevert(VeriLogRegistry.ZeroAgentId.selector);
        registry.anchorEpoch(bytes32(0), ROOT, 1);
        vm.expectRevert(VeriLogRegistry.ZeroMerkleRoot.selector);
        registry.anchorEpoch(AGENT, bytes32(0), 1);
        vm.expectRevert(VeriLogRegistry.ZeroLogCount.selector);
        registry.anchorEpoch(AGENT, ROOT, 0);
        vm.stopPrank();
        assertEq(registry.latestEpoch(AGENT), 0);
    }

    function test_AnchorStructUsesTwoSlots() public {
        vm.prank(anchorer);
        registry.anchorEpoch(AGENT, ROOT, 7);
        // agentAnchors is storage slot 1 (slot 0 is AccessControl._roles).
        bytes32 outer = keccak256(abi.encode(AGENT, uint256(1)));
        bytes32 base = keccak256(abi.encode(uint256(1), outer));
        assertEq(vm.load(address(registry), base), ROOT);
        uint256 packed = uint256(vm.load(address(registry), bytes32(uint256(base) + 1)));
        assertEq(uint64(packed), uint64(block.timestamp));
        assertEq(uint32(packed >> 64), 7);
        assertEq(vm.load(address(registry), bytes32(uint256(base) + 2)), bytes32(0));
    }

    // -------------------------------------------------------------- proofs

    /// Every proof in the Go-generated vectors verifies on chain, and the
    /// recomputed roots match the Go roots.
    function test_GoGeneratedVectorsVerify() public {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/../testdata/merkle_vectors.json"));
        uint256 treeCount = json.readUint(".treeCount");
        assertGt(treeCount, 0);
        uint256 checked;
        for (uint256 t = 0; t < treeCount; t++) {
            string memory tp = string.concat(".trees[", vm.toString(t), "]");
            bytes32 root = json.readBytes32(string.concat(tp, ".root"));
            bytes32[] memory leaves = json.readBytes32Array(string.concat(tp, ".leaves"));
            assertEq(leaves.length, json.readUint(string.concat(tp, ".leafCount")));

            vm.prank(anchorer);
            uint256 epoch = registry.anchorEpoch(AGENT, root, uint32(leaves.length));

            for (uint256 i = 0; i < leaves.length; i++) {
                bytes32[] memory proof = _readProof(json, tp, i);
                assertTrue(registry.verifyProof(leaves[i], proof, root), "verifyProof");
                assertTrue(registry.verifyAnchoredLeaf(AGENT, epoch, leaves[i], proof), "verifyAnchoredLeaf");
                // A neighbouring leaf must not verify with this proof.
                if (leaves.length > 1) {
                    assertFalse(registry.verifyProof(leaves[(i + 1) % leaves.length], proof, root));
                }
                checked++;
            }
        }
        assertGt(checked, 50);
    }

    /// The canonical-event vectors (SHA-256 content digest, keccak leaf,
    /// keccak agent key) agree with Solidity's own hashing.
    function test_GoCanonicalVectorsHashing() public view {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/../testdata/canonical_vectors.json"));
        for (uint256 i = 0; i < 8; i++) {
            string memory cp = string.concat(".cases[", vm.toString(i), "]");
            bytes memory canonicalEvent = bytes(json.readString(string.concat(cp, ".canonical_event")));
            bytes32 digest = sha256(canonicalEvent);
            assertEq(digest, json.readBytes32(string.concat(cp, ".content_digest")));
            assertEq(keccak256(abi.encodePacked(digest)), json.readBytes32(string.concat(cp, ".leaf")));
            assertEq(
                keccak256(bytes(json.readString(string.concat(cp, ".agent_id")))),
                json.readBytes32(string.concat(cp, ".agent_key"))
            );
        }
    }

    function test_VerifyAnchoredLeafRevertsForMissingEpoch() public {
        vm.expectRevert(abi.encodeWithSelector(VeriLogRegistry.EpochNotAnchored.selector, AGENT, uint256(1)));
        registry.verifyAnchoredLeaf(AGENT, 1, ROOT, new bytes32[](0));
    }

    /// Flipping any bit of the leaf, or of any proof element, breaks verification.
    function testFuzz_TamperedProofFails(uint256 treePick, uint256 leafPick, uint256 elemPick, uint8 bitPick)
        public
        view
    {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/../testdata/merkle_vectors.json"));
        uint256 t = bound(treePick, 0, json.readUint(".treeCount") - 1);
        string memory tp = string.concat(".trees[", vm.toString(t), "]");
        bytes32 root = json.readBytes32(string.concat(tp, ".root"));
        bytes32[] memory leaves = json.readBytes32Array(string.concat(tp, ".leaves"));
        uint256 i = bound(leafPick, 0, leaves.length - 1);
        bytes32[] memory proof = _readProof(json, tp, i);
        bytes32 mask = bytes32(uint256(1) << bitPick);

        assertTrue(registry.verifyProof(leaves[i], proof, root));
        assertFalse(registry.verifyProof(leaves[i] ^ mask, proof, root), "tampered leaf accepted");
        assertFalse(registry.verifyProof(leaves[i], proof, root ^ mask), "tampered root accepted");
        if (proof.length > 0) {
            uint256 j = bound(elemPick, 0, proof.length - 1);
            proof[j] = proof[j] ^ mask;
            assertFalse(registry.verifyProof(leaves[i], proof, root), "tampered proof accepted");
        }
    }

    /// A random leaf with a random proof does not verify against a fixed root.
    function testFuzz_RandomLeafRejected(bytes32 leaf, bytes32 sibling) public view {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;
        bytes32 root = keccak256("some-anchored-root");
        vm.assume(_hashPair(leaf, sibling) != root);
        assertFalse(registry.verifyProof(leaf, proof, root));
    }

    function testFuzz_AnchorEpochSequence(bytes32 agent, bytes32 root, uint32 count, uint8 rounds) public {
        vm.assume(agent != bytes32(0) && root != bytes32(0) && count != 0);
        uint256 n = bound(rounds, 1, 20);
        vm.startPrank(anchorer);
        for (uint256 k = 1; k <= n; k++) {
            assertEq(registry.anchorEpoch(agent, root, count), k);
        }
        vm.stopPrank();
        assertEq(registry.latestEpoch(agent), n);
    }

    // -------------------------------------------------------------- helpers

    function _readProof(string memory json, string memory tp, uint256 i) internal pure returns (bytes32[] memory) {
        string memory key = string.concat(tp, ".proofs[", vm.toString(i), "]");
        // An empty JSON array (single-leaf tree) cannot be type-inferred by the parser.
        bytes memory raw = vm.parseJson(json, key);
        if (raw.length <= 64) return new bytes32[](0);
        return json.readBytes32Array(key);
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }
}
