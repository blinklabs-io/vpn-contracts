// VPN Payment Contract Simulator for Testing
// Copyright (C) 2025 Blink Labs
// SPDX-License-Identifier: Apache-2.0

import {
  type CircuitContext,
  QueryContext,
  sampleContractAddress,
  constructorContext,
  convert_bigint_to_Uint8Array,
} from "@midnight-ntwrk/compact-runtime";
import {
  Contract,
  type Ledger,
  type PaymentReceipt,
  ledger,
  pureCircuits,
} from "../managed/vpn-payment/contract/index.cjs";
import {
  type VPNPaymentPrivateState,
  witnesses,
} from "../witnesses.js";

/**
 * Simulator for testing the VPN Payment contract
 */
export class VPNPaymentSimulator {
  readonly contract: Contract<VPNPaymentPrivateState>;
  circuitContext: CircuitContext<VPNPaymentPrivateState>;

  constructor(secretKey: Uint8Array, providerCommitment: Uint8Array) {
    this.contract = new Contract<VPNPaymentPrivateState>(witnesses);

    const {
      currentPrivateState,
      currentContractState,
      currentZswapLocalState,
    } = this.contract.initialState(
      constructorContext(
        { secretKey, paymentAmount: 0n },
        "0".repeat(64)
      ),
      providerCommitment
    );

    this.circuitContext = {
      currentPrivateState,
      currentZswapLocalState,
      originalState: currentContractState,
      transactionContext: new QueryContext(
        currentContractState.data,
        sampleContractAddress()
      ),
    };
  }

  /**
   * Switch to a different user (different secret key)
   */
  public switchUser(secretKey: Uint8Array): void {
    this.circuitContext.currentPrivateState = {
      secretKey,
      paymentAmount: 0n,
    };
  }

  /**
   * Set the payment amount for the current user
   */
  public setPaymentAmount(amount: bigint): void {
    this.circuitContext.currentPrivateState = {
      ...this.circuitContext.currentPrivateState,
      paymentAmount: amount,
    };
  }

  /**
   * Get the current ledger state
   */
  public getLedger(): Ledger {
    return ledger(this.circuitContext.transactionContext.state);
  }

  /**
   * Get the current private state
   */
  public getPrivateState(): VPNPaymentPrivateState {
    return this.circuitContext.currentPrivateState;
  }

  /**
   * Pay for VPN access and get a payment receipt
   */
  public payForVPN(pricingTier: bigint, region: Uint8Array): PaymentReceipt {
    const result = this.contract.impureCircuits.payForVPN(
      this.circuitContext,
      pricingTier,
      region
    );
    this.circuitContext = result.context;
    return result.result;
  }

  /**
   * Verify a payment exists (returns nullifier count)
   */
  public verifyPaymentExists(nullifier: Uint8Array): bigint {
    const result = this.contract.impureCircuits.verifyPaymentExists(
      this.circuitContext,
      nullifier
    );
    this.circuitContext = result.context;
    return result.result;
  }

  /**
   * Update the provider commitment
   */
  public updateProvider(newProviderCommitment: Uint8Array): void {
    const result = this.contract.impureCircuits.updateProvider(
      this.circuitContext,
      newProviderCommitment
    );
    this.circuitContext = result.context;
  }

  /**
   * Generate a nullifier using pure circuit (for testing)
   */
  public generateNullifier(
    secretKey: Uint8Array,
    sequence: Uint8Array,
    tierIndex: Uint8Array
  ): Uint8Array {
    return pureCircuits.generateNullifier(secretKey, sequence, tierIndex);
  }

  /**
   * Generate commitment hash using pure circuit (for testing)
   */
  public commitmentHash(data: Uint8Array, salt: Uint8Array): Uint8Array {
    return pureCircuits.commitmentHash(data, salt);
  }
}
