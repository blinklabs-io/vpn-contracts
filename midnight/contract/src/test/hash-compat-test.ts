// Hash Compatibility Test
// Compare persistentHash (Midnight) with Poseidon (Halo2)

import { setNetworkId, NetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { VPNPaymentSimulator } from "./vpn-payment-simulator.js";
import { bytesToHex, createProviderCommitment } from "./utils.js";

setNetworkId(NetworkId.Undeployed);

// Use deterministic test inputs (all zeros for simplicity)
const secretKey = new Uint8Array(32);
secretKey[0] = 0x01;  // Just set first byte to 1

const sequence = new Uint8Array(32);
sequence[31] = 0x01;  // sequence = 1 (big-endian)

const tierIndex = new Uint8Array(32);
tierIndex[31] = 0x00;  // tier = 0

// Create simulator
const providerCommitment = createProviderCommitment("test_provider");
const simulator = new VPNPaymentSimulator(secretKey, providerCommitment);

// Generate nullifier using pure circuit
const nullifier = simulator.generateNullifier(secretKey, sequence, tierIndex);

console.log("=== Hash Compatibility Test ===");
console.log("");
console.log("Inputs (as hex):");
console.log("  secretKey:", bytesToHex(secretKey));
console.log("  sequence: ", bytesToHex(sequence));
console.log("  tierIndex:", bytesToHex(tierIndex));
console.log("");
console.log("Output:");
console.log("  nullifier:", bytesToHex(nullifier));
console.log("");
console.log("Use these same inputs in Rust Poseidon to compare.");
