// Test utilities for VPN Payment Contract
// Copyright (C) 2025 Blink Labs
// SPDX-License-Identifier: Apache-2.0

import { randomBytes as cryptoRandomBytes } from "crypto";

/**
 * Generate random bytes for testing
 */
export function randomBytes(length: number): Uint8Array {
  return new Uint8Array(cryptoRandomBytes(length));
}

/**
 * Convert a hex string to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Create a 32-byte region code from a string
 */
export function regionToBytes(region: string): Uint8Array {
  const bytes = new Uint8Array(32);
  const encoded = new TextEncoder().encode(region);
  bytes.set(encoded.slice(0, 32));
  return bytes;
}

/**
 * Create a provider commitment hash (simulated)
 */
export function createProviderCommitment(providerAddress: string): Uint8Array {
  // In production, this would be a proper hash of the Cardano address
  const bytes = new Uint8Array(32);
  const encoded = new TextEncoder().encode(providerAddress);
  bytes.set(encoded.slice(0, 32));
  return bytes;
}
