// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {VeriLogRegistry} from "../src/VeriLogRegistry.sol";

/// @notice Deploys VeriLogRegistry.
/// Environment:
///   VERILOG_ADMIN    admin address (default: the broadcasting account)
///   VERILOG_ANCHORER anchorer address, i.e. the daemon signer (default: the broadcasting account)
/// Usage:
///   forge script script/Deploy.s.sol --rpc-url $RPC --private-key $KEY --broadcast
contract Deploy is Script {
    function run() external returns (VeriLogRegistry registry) {
        vm.startBroadcast();
        (, address sender,) = vm.readCallers();
        address admin = vm.envOr("VERILOG_ADMIN", sender);
        address anchorer = vm.envOr("VERILOG_ANCHORER", sender);
        registry = new VeriLogRegistry(admin, anchorer);
        vm.stopBroadcast();

        console2.log("VeriLogRegistry deployed at", address(registry));
        console2.log("admin", admin);
        console2.log("anchorer", anchorer);
    }
}
