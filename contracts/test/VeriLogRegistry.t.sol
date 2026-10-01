// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, stdJson} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {VeriLogRegistry} from "../src/VeriLogRegistry.sol";

contract VeriLogRegistryTest is Test {
    using stdJson for string;

    event LogAnchored(
        bytes32 indexed agentId, uint256 indexed epochId, bytes32 merkleRoot, uint32 logCount, uint64 timestamp
    );

    VeriLogRegistry internal registry;
    address internal admin = makeAddr("admin");
    address internal anchorer = makeAddr("anchorer");
    address internal stranger = makeAddr("stranger");

    bytes32 internal constant AGENT = keccak256("agent-alpha");
    bytes32 internal constant ROOT = keccak256("root");

    function setUp() public {
        registry = new VeriLogRegistry(admin, anchorer);
    }

    // ----------------------------------------------------------------- deploy

    function test_ConstructorGrantsRoles() public view {
        assertTrue(registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(registry.hasRole(registry.ANCHORER_ROLE(), anchorer));
        assertFalse(registry.hasRole(registry.ANCHORER_ROLE(), admin));
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
