import type * as __compactRuntime from '@midnight-ntwrk/compact-runtime';

export enum PaymentStatus { PENDING = 0, COMPLETED = 1, EXPORTED = 2 }

export type PricingTier = { index: bigint;
                            priceInLovelace: bigint;
                            durationMs: bigint
                          };

export type PaymentReceipt = { nullifier: Uint8Array;
                               pricingTier: bigint;
                               region: Uint8Array;
                               timestamp: bigint;
                               providerCommitment: Uint8Array
                             };

export type Witnesses<T> = {
  userSecretKey(context: __compactRuntime.WitnessContext<Ledger, T>): [T, Uint8Array];
}

export type ImpureCircuits<T> = {
  payForVPN(context: __compactRuntime.CircuitContext<T>,
            pricingTier_0: bigint,
            region_0: Uint8Array): __compactRuntime.CircuitResults<T, PaymentReceipt>;
  verifyPaymentExists(context: __compactRuntime.CircuitContext<T>,
                      expectedNullifier_0: Uint8Array): __compactRuntime.CircuitResults<T, bigint>;
  updateProvider(context: __compactRuntime.CircuitContext<T>,
                 newProviderCommitment_0: Uint8Array): __compactRuntime.CircuitResults<T, []>;
}

export type PureCircuits = {
  generateNullifier(secretKey_0: Uint8Array,
                    seq_0: Uint8Array,
                    tierIndex_0: Uint8Array): Uint8Array;
  commitmentHash(data_0: Uint8Array, salt_0: Uint8Array): Uint8Array;
}

export type Circuits<T> = {
  generateNullifier(context: __compactRuntime.CircuitContext<T>,
                    secretKey_0: Uint8Array,
                    seq_0: Uint8Array,
                    tierIndex_0: Uint8Array): __compactRuntime.CircuitResults<T, Uint8Array>;
  commitmentHash(context: __compactRuntime.CircuitContext<T>,
                 data_0: Uint8Array,
                 salt_0: Uint8Array): __compactRuntime.CircuitResults<T, Uint8Array>;
  payForVPN(context: __compactRuntime.CircuitContext<T>,
            pricingTier_0: bigint,
            region_0: Uint8Array): __compactRuntime.CircuitResults<T, PaymentReceipt>;
  verifyPaymentExists(context: __compactRuntime.CircuitContext<T>,
                      expectedNullifier_0: Uint8Array): __compactRuntime.CircuitResults<T, bigint>;
  updateProvider(context: __compactRuntime.CircuitContext<T>,
                 newProviderCommitment_0: Uint8Array): __compactRuntime.CircuitResults<T, []>;
}

export type Ledger = {
  readonly providerCommitment: Uint8Array;
  readonly pricingTierCount: bigint;
  readonly totalPayments: bigint;
  readonly nullifierCount: bigint;
  readonly sequence: bigint;
}

export type ContractReferenceLocations = any;

export declare const contractReferenceLocations : ContractReferenceLocations;

export declare class Contract<T, W extends Witnesses<T> = Witnesses<T>> {
  witnesses: W;
  circuits: Circuits<T>;
  impureCircuits: ImpureCircuits<T>;
  constructor(witnesses: W);
  initialState(context: __compactRuntime.ConstructorContext<T>,
               providerAddr_0: Uint8Array): __compactRuntime.ConstructorResult<T>;
}

export declare function ledger(state: __compactRuntime.StateValue): Ledger;
export declare const pureCircuits: PureCircuits;
