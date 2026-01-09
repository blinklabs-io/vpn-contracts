// VPN Payment Contract Tests
// Copyright (C) 2025 Blink Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeEach } from "vitest";
import {
  NetworkId,
  setNetworkId,
} from "@midnight-ntwrk/midnight-js-network-id";
import { VPNPaymentSimulator } from "./vpn-payment-simulator.js";
import {
  randomBytes,
  regionToBytes,
  createProviderCommitment,
  bytesToHex,
} from "./utils.js";

// Set network to undeployed for testing
setNetworkId(NetworkId.Undeployed);

describe("VPN Payment Contract", () => {
  let simulator: VPNPaymentSimulator;
  let userSecretKey: Uint8Array;
  let providerCommitment: Uint8Array;

  beforeEach(() => {
    userSecretKey = randomBytes(32);
    providerCommitment = createProviderCommitment("addr_test1provider123");
    simulator = new VPNPaymentSimulator(userSecretKey, providerCommitment);
  });

  describe("Initialization", () => {
    it("generates initial ledger state deterministically", () => {
      const key = randomBytes(32);
      const provider = createProviderCommitment("test_provider");
      const simulator1 = new VPNPaymentSimulator(key, provider);
      const simulator2 = new VPNPaymentSimulator(key, provider);
      expect(simulator1.getLedger()).toEqual(simulator2.getLedger());
    });

    it("properly initializes ledger state", () => {
      const ledger = simulator.getLedger();
      expect(ledger.sequence).toEqual(1n);
      expect(ledger.totalPayments).toEqual(0n);
      expect(ledger.nullifierCount).toEqual(0n);
      expect(ledger.pricingTierCount).toEqual(3n);
      expect(ledger.providerCommitment).toEqual(providerCommitment);
    });

    it("properly initializes private state", () => {
      const privateState = simulator.getPrivateState();
      expect(privateState.secretKey).toEqual(userSecretKey);
      expect(privateState.paymentAmount).toEqual(0n);
    });
  });

  describe("Payment Processing", () => {
    it("processes a payment for tier 0 (1 hour)", () => {
      const region = regionToBytes("us-east");
      const receipt = simulator.payForVPN(0n, region);

      expect(receipt.pricingTier).toEqual(0n);
      expect(receipt.region).toEqual(region);
      expect(receipt.providerCommitment).toEqual(providerCommitment);
      expect(receipt.nullifier.length).toEqual(32);

      const ledger = simulator.getLedger();
      expect(ledger.totalPayments).toEqual(1n);
      expect(ledger.nullifierCount).toEqual(1n);
      expect(ledger.sequence).toEqual(2n);
    });

    it("processes a payment for tier 1 (3 days)", () => {
      const region = regionToBytes("eu-west");
      const receipt = simulator.payForVPN(1n, region);

      expect(receipt.pricingTier).toEqual(1n);
      expect(receipt.region).toEqual(region);
    });

    it("processes a payment for tier 2 (1 year)", () => {
      const region = regionToBytes("asia-pacific");
      const receipt = simulator.payForVPN(2n, region);

      expect(receipt.pricingTier).toEqual(2n);
      expect(receipt.region).toEqual(region);
    });

    it("rejects invalid pricing tier (3)", () => {
      const region = regionToBytes("us-east");
      expect(() => simulator.payForVPN(3n, region)).toThrow(
        "failed assert: Invalid pricing tier"
      );
    });

    it("generates unique nullifiers for each payment", () => {
      const region = regionToBytes("us-east");

      const receipt1 = simulator.payForVPN(0n, region);
      const receipt2 = simulator.payForVPN(1n, region);

      expect(receipt1.nullifier).not.toEqual(receipt2.nullifier);
    });

    it("generates different nullifiers for different users", () => {
      const region = regionToBytes("us-east");

      const receipt1 = simulator.payForVPN(0n, region);

      // Switch to different user
      simulator.switchUser(randomBytes(32));
      const receipt2 = simulator.payForVPN(0n, region);

      expect(receipt1.nullifier).not.toEqual(receipt2.nullifier);
    });

    it("increments counters correctly after multiple payments", () => {
      const region = regionToBytes("us-east");

      simulator.payForVPN(0n, region);
      simulator.payForVPN(1n, region);
      simulator.payForVPN(2n, region);

      const ledger = simulator.getLedger();
      expect(ledger.totalPayments).toEqual(3n);
      expect(ledger.nullifierCount).toEqual(3n);
      expect(ledger.sequence).toEqual(4n);
    });
  });

  describe("Payment Receipt Structure", () => {
    it("receipt contains all required fields for Cardano proof", () => {
      const region = regionToBytes("us-east");
      const receipt = simulator.payForVPN(1n, region);

      // All fields required for Cardano ZK proof submission
      expect(receipt.nullifier).toBeDefined();
      expect(receipt.nullifier.length).toEqual(32);

      expect(receipt.pricingTier).toBeDefined();
      expect(typeof receipt.pricingTier).toBe("bigint");

      expect(receipt.region).toBeDefined();
      expect(receipt.region.length).toEqual(32);

      expect(receipt.timestamp).toBeDefined();
      expect(typeof receipt.timestamp).toBe("bigint");

      expect(receipt.providerCommitment).toBeDefined();
      expect(receipt.providerCommitment.length).toEqual(32);
    });

    it("receipt nullifier is deterministic given same inputs", () => {
      const key = randomBytes(32);
      const provider = createProviderCommitment("provider");
      const region = regionToBytes("us-east");

      const sim1 = new VPNPaymentSimulator(key, provider);
      const sim2 = new VPNPaymentSimulator(key, provider);

      const receipt1 = sim1.payForVPN(0n, region);
      const receipt2 = sim2.payForVPN(0n, region);

      expect(receipt1.nullifier).toEqual(receipt2.nullifier);
    });
  });

  describe("Provider Management", () => {
    it("allows updating provider commitment", () => {
      const newProvider = createProviderCommitment("new_provider_address");
      simulator.updateProvider(newProvider);

      const ledger = simulator.getLedger();
      expect(ledger.providerCommitment).toEqual(newProvider);
    });

    it("new payments use updated provider commitment", () => {
      const newProvider = createProviderCommitment("new_provider");
      simulator.updateProvider(newProvider);

      const region = regionToBytes("us-east");
      const receipt = simulator.payForVPN(0n, region);

      expect(receipt.providerCommitment).toEqual(newProvider);
    });
  });

  describe("Pure Circuits", () => {
    it("generates consistent nullifiers", () => {
      const secretKey = randomBytes(32);
      const seq = new Uint8Array(32);
      seq[31] = 1; // sequence = 1
      const tier = new Uint8Array(32);
      tier[31] = 0; // tier = 0

      const nullifier1 = simulator.generateNullifier(secretKey, seq, tier);
      const nullifier2 = simulator.generateNullifier(secretKey, seq, tier);

      expect(nullifier1).toEqual(nullifier2);
    });

    it("generates different nullifiers for different sequences", () => {
      const secretKey = randomBytes(32);
      const seq1 = new Uint8Array(32);
      seq1[31] = 1;
      const seq2 = new Uint8Array(32);
      seq2[31] = 2;
      const tier = new Uint8Array(32);

      const nullifier1 = simulator.generateNullifier(secretKey, seq1, tier);
      const nullifier2 = simulator.generateNullifier(secretKey, seq2, tier);

      expect(nullifier1).not.toEqual(nullifier2);
    });

    it("generates commitment hash correctly", () => {
      const data = randomBytes(32);
      const salt = randomBytes(32);

      const hash1 = simulator.commitmentHash(data, salt);
      const hash2 = simulator.commitmentHash(data, salt);

      expect(hash1).toEqual(hash2);
      expect(hash1.length).toEqual(32);
    });
  });

  describe("Multi-User Scenarios", () => {
    it("supports multiple users making payments", () => {
      const region = regionToBytes("us-east");

      // User 1 pays
      const receipt1 = simulator.payForVPN(0n, region);

      // Switch to User 2
      simulator.switchUser(randomBytes(32));
      const receipt2 = simulator.payForVPN(1n, region);

      // Switch to User 3
      simulator.switchUser(randomBytes(32));
      const receipt3 = simulator.payForVPN(2n, region);

      // All receipts should have different nullifiers
      expect(receipt1.nullifier).not.toEqual(receipt2.nullifier);
      expect(receipt2.nullifier).not.toEqual(receipt3.nullifier);
      expect(receipt1.nullifier).not.toEqual(receipt3.nullifier);

      // Total payments should be 3
      expect(simulator.getLedger().totalPayments).toEqual(3n);
    });
  });

  describe("Export Format for Cardano", () => {
    it("receipt can be serialized to JSON for Cardano proof file", () => {
      const region = regionToBytes("us-east");
      const receipt = simulator.payForVPN(1n, region);

      // Create proof file format matching scripts/07-mint-vpn-midnight.sh
      const proofFile = {
        zk_proof: bytesToHex(new Uint8Array(288)), // Placeholder proof bytes
        nullifier: bytesToHex(receipt.nullifier),
        state_root: bytesToHex(randomBytes(32)), // Midnight state root
        selection: Number(receipt.pricingTier),
        region: bytesToHex(receipt.region),
      };

      // Verify structure
      expect(typeof proofFile.zk_proof).toBe("string");
      expect(typeof proofFile.nullifier).toBe("string");
      expect(proofFile.nullifier.length).toBe(64); // 32 bytes = 64 hex chars
      expect(typeof proofFile.state_root).toBe("string");
      expect(typeof proofFile.selection).toBe("number");
      expect([0, 1, 2]).toContain(proofFile.selection);
      expect(typeof proofFile.region).toBe("string");
    });
  });
});
