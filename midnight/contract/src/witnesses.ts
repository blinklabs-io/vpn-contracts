// VPN Payment Contract Witnesses
// Copyright (C) 2025 Blink Labs
// SPDX-License-Identifier: Apache-2.0
//
// This file defines the witness functions that provide private inputs
// to the VPN payment contract circuits.

import type { WitnessContext } from "@midnight-ntwrk/compact-runtime";
import type { Ledger } from "./managed/vpn-payment/contract/index.cjs";

// ============================================================================
// Private State Types
// ============================================================================

/**
 * Private state for VPN payment operations
 * Contains user secrets that should never be exposed on-chain
 */
export type VPNPaymentPrivateState = {
  /** User's secret key for generating unique nullifiers */
  readonly secretKey: Uint8Array;
  /** Payment amount in lovelace (for validation) */
  readonly paymentAmount: bigint;
};

/**
 * Create initial private state for a user
 */
export const createVPNPaymentPrivateState = (
  secretKey: Uint8Array,
  paymentAmount: bigint = 0n
): VPNPaymentPrivateState => ({
  secretKey,
  paymentAmount,
});

// ============================================================================
// Witness Functions
// ============================================================================

/**
 * Witness functions that provide private inputs to the contract circuits
 *
 * Each witness function:
 * 1. Receives a WitnessContext with ledger state and private state
 * 2. Returns a tuple of [newPrivateState, returnValue]
 */
export const witnesses = {
  /**
   * Provides the user's secret key for nullifier generation
   * This key is never revealed on-chain, only used in ZK proofs
   */
  userSecretKey: ({
    privateState,
  }: WitnessContext<Ledger, VPNPaymentPrivateState>): [
    VPNPaymentPrivateState,
    Uint8Array,
  ] => [privateState, privateState.secretKey],
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Generate a random secret key for a new user
 */
export const generateSecretKey = (): Uint8Array => {
  const key = new Uint8Array(32);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(key);
  } else {
    // Fallback for Node.js
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { randomBytes } = require("crypto");
    const buf = randomBytes(32);
    key.set(buf);
  }
  return key;
};

/**
 * Convert a hex string to Uint8Array
 */
export const hexToBytes = (hex: string): Uint8Array => {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return bytes;
};

/**
 * Convert Uint8Array to hex string
 */
export const bytesToHex = (bytes: Uint8Array): string => {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
};
