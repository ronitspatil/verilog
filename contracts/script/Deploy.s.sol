// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {VeriLogRegistry} from "../src/VeriLogRegistry.sol";

/// @notice Deploys VeriLogRegistry.
/// Environment:
///   VERILOG_ANCHORER anchorer address, i.e. the daemon signer (required). It must
///                    differ from the admin: the anchorer never holds KEY_ADMIN_ROLE.
///   VERILOG_ADMIN    admin address (default: the broadcasting account). Receives
///                    DEFAULT_ADMIN_ROLE and KEY_ADMIN_ROLE. Use a dev key locally
///                    and hand both roles to a multisig in production (see README).
/// Usage:
///   VERILOG_ANCHORER=0xDaemon forge script script/Deploy.s.sol --rpc-url $RPC --private-key $ADMIN_KEY --broadcast
contract Deploy is Script {
    function run() external returns (VeriLogRegistry registry) {
        vm.startBroadcast();
        (, address sender,) = vm.readCallers();
        address admin = vm.envOr("VERILOG_ADMIN", sender);
        address anchorer = vm.envAddress("VERILOG_ANCHORER");
        require(
            anchorer != admin, "VERILOG_ANCHORER must differ from the admin (the anchorer never holds KEY_ADMIN_ROLE)"
        );
        registry = new VeriLogRegistry(admin, anchorer);
        vm.stopBroadcast();

        console2.log("VeriLogRegistry deployed at", address(registry));
        console2.log("admin (DEFAULT_ADMIN_ROLE, KEY_ADMIN_ROLE)", admin);
        console2.log("anchorer (ANCHORER_ROLE)", anchorer);
    }
}
