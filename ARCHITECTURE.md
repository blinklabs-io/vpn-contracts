# VPN Contracts Architecture

This document describes the architecture of the Nabu VPN smart contracts, including both the standard ADA payment flow and the Midnight private payment flow.

## Table of Contents

1. Overview
2. Smart Contract Architecture
3. ADA Payment Flow
4. Midnight Payment Flow
5. Security Model
6. Deployment Architecture
7. Integration Points

---

## 1. Overview

The Nabu VPN system uses Cardano smart contracts to manage VPN subscription access. Users purchase VPN access by minting unique tokens that represent their subscription. The system supports two payment methods:

- ADA payments: Direct payment using the audited VPN contracts
- Midnight payments: Private payment using ZK proofs via a separate escrow contract

### Design Principles

1. Preserve audit validity: The original VPN contracts (audited by UTxO Company, November 2025) remain unchanged
2. On-chain verification: All payment proofs are verified on-chain for trustless operation
3. Privacy preservation: Midnight payments hide the payment amount and payer identity
4. Double-spend prevention: Nullifier tokens prevent replay of ZK proofs

---

## 2. Smart Contract Architecture

### 2.1 Contract Overview

```
vpn-contracts/
├── validators/
│   ├── vpn.ak              # Main VPN validator (AUDITED)
│   ├── nft.ak              # Reference NFT validator (AUDITED)
│   ├── midnight_escrow.ak  # Midnight escrow validator (NEW)
│   └── escrow_nft.ak       # Escrow config NFT validator (NEW)
├── lib/
│   ├── types.ak            # VPN types (AUDITED)
│   ├── escrow_types.ak     # Escrow types (NEW)
│   ├── utilities.ak        # Shared utilities
│   └── halo2/              # Halo2 ZK verifier library (NEW)
└── circuits/
    └── src/                # Rust Halo2 circuits for proof generation
```

### 2.2 VPN Validator (vpn.ak)

The main VPN validator handles both minting and spending of VPN access tokens. It is parameterized by:

- wait_time: Delay before provider can burn expired tokens
- reference_policy_id: Policy ID of the reference NFT
- provider_address: Address to receive payments

Redeemer Actions:

| Action | Purpose |
|--------|---------|
| MintVPNAccess | Mint new VPN token with ADA payment |
| ExtendVPNAccess | Renew subscription or transfer ownership |
| BurnVPNAccess | Burn expired token (owner or provider) |
| UpdateReferenceData | Update pricing and regions (provider only) |

### 2.3 Reference NFT Validator (nft.ak)

A one-shot NFT validator that creates a unique reference NFT. This NFT identifies the UTxO containing pricing and region data that VPN minting transactions reference.

### 2.4 Midnight Escrow Validator (midnight_escrow.ak)

The escrow validator handles ZK proof verification and fund release for Midnight payments. It is parameterized by:

- escrow_config_policy_id: Policy ID of the escrow config NFT
- vpn_reference_policy_id: Policy ID of the VPN reference NFT
- provider_address: Address to receive payments

Redeemer Actions:

| Action | Purpose |
|--------|---------|
| ReleaseFunds | Verify ZK proof and release ADA for VPN minting |
| WithdrawExcess | Provider withdraws excess funds from escrow |
| DepositFunds | Provider deposits more funds into escrow |
| MintNullifier | Mint nullifier token to prevent proof replay |

### 2.5 Escrow Config NFT Validator (escrow_nft.ak)

A one-shot NFT validator for the escrow configuration UTxO. Similar to the VPN reference NFT pattern.

---

## 3. ADA Payment Flow

The ADA payment flow uses the audited VPN contracts directly. Users pay ADA to the provider and receive a VPN access token.

### 3.1 Transaction Structure

```
INPUTS:
  - User UTxO (contains ADA for payment + tx fees)

REFERENCE INPUTS:
  - VPN Reference Data (pricing, regions)

MINTS:
  - VPN Policy: +1 VPN access token

OUTPUTS:
  - Provider: ADA payment (exact price for selected tier)
  - User: VPN token + VPNData datum (at script address)

REDEEMERS:
  - VPN mint: MintVPNAccess { owner, region, selection, tx_ref }

SIGNATORIES:
  - User (owner)
```

### 3.2 Sequence Diagram

```
┌──────┐     ┌──────────┐     ┌─────────┐     ┌─────────┐
│ User │     │ Frontend │     │ Indexer │     │ Cardano │
└──┬───┘     └────┬─────┘     └────┬────┘     └────┬────┘
   │              │                │               │
   │ 1. Select    │                │               │
   │    tier +    │                │               │
   │    region    │                │               │
   │─────────────>│                │               │
   │              │                │               │
   │              │ 2. POST        │               │
   │              │    /api/signup │               │
   │              │───────────────>│               │
   │              │                │               │
   │              │ 3. Unsigned TX │               │
   │              │<───────────────│               │
   │              │                │               │
   │ 4. Sign TX   │                │               │
   │<─────────────│                │               │
   │              │                │               │
   │ 5. Submit    │                │               │
   │─────────────────────────────────────────────>│
   │              │                │               │
   │              │                │ 6. Validate   │
   │              │                │    on-chain   │
   │              │                │<──────────────│
   │              │                │               │
   │ 7. VPN       │                │               │
   │    active    │                │               │
   │<─────────────────────────────────────────────│
```

### 3.3 Validation Rules

The VPN validator checks:

1. Token name is derived from consumed UTxO (blake2b_256 of output reference)
2. Exactly one token is minted
3. Selected region is in the allowed regions list
4. Provider receives exact payment amount for selected tier
5. Owner has signed the transaction
6. The referenced UTxO is consumed (ensures unique token name)
7. Output contains correct VPNData datum with calculated expiration

### 3.4 VPNData Datum Structure

```
VPNData {
  owner: VerificationKeyHash,    # Public key hash of token owner
  region: ByteArray,             # Selected region code
  expiration_time: Int,          # POSIX time in milliseconds
}
```

---

## 4. Midnight Payment Flow

The Midnight payment flow uses a separate escrow contract to preserve the audited VPN contracts. Users pay NIGHT tokens on the Midnight blockchain, receive a ZK proof, and use that proof to mint a VPN token on Cardano.

### 4.1 Overview

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Midnight  │     │   Cardano   │     │   Cardano   │
│  Blockchain │     │   Escrow    │     │     VPN     │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
   Pay NIGHT          Verify proof        Mint VPN token
   Generate           Release ADA         (standard flow)
   nullifier          Mint nullifier
   Create proof
```

### 4.2 Security Model

The Midnight integration provides privacy guarantees:

- Midnight: Verifies the NIGHT payment occurred, generates a nullifier using persistentHash
- Halo2 Circuit: Proves payment_amount >= tier_price without revealing the actual amount
- Cardano Escrow: Verifies the ZK proof on-chain, mints nullifier to prevent replay
- Cardano VPN: Receives ADA payment from escrow, mints VPN token (unchanged logic)

### 4.3 Transaction Structure

```
INPUTS:
  - Escrow UTxO (contains ADA pool funded by provider)
  - User UTxO (for tx_ref to derive VPN token name)

REFERENCE INPUTS:
  - VPN Reference Data (pricing, regions)
  - Escrow Config (verifier settings, tier prices, enabled flag)

MINTS:
  - Escrow Policy: +1 nullifier token
  - VPN Policy: +1 VPN access token

OUTPUTS:
  - Provider: ADA payment (from escrow funds)
  - User: VPN token + VPNData datum
  - Escrow: Remaining funds (continuing UTxO)

REDEEMERS:
  - Escrow spend: ReleaseFunds { zk_proof, nullifier, selection, ... }
  - Escrow mint: MintNullifier { nullifier }
  - VPN mint: MintVPNAccess { owner, region, selection, tx_ref }

SIGNATORIES:
  - User (owner)
```

### 4.4 Sequence Diagram

```
┌──────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐  ┌─────────┐
│ User │  │ Frontend │  │ Midnight │  │ Indexer │  │ Cardano │
└──┬───┘  └────┬─────┘  └────┬─────┘  └────┬────┘  └────┬────┘
   │           │             │             │            │
   │ 1. Select │             │             │            │
   │    tier   │             │             │            │
   │──────────>│             │             │            │
   │           │             │             │            │
   │           │ 2. Initiate │             │            │
   │           │    payment  │             │            │
   │           │────────────>│             │            │
   │           │             │             │            │
   │ 3. Pay    │             │             │            │
   │    NIGHT  │             │             │            │
   │────────────────────────>│             │            │
   │           │             │             │            │
   │           │             │ 4. Generate │            │
   │           │             │    nullifier│            │
   │           │             │    + proof  │            │
   │           │             │             │            │
   │           │ 5. Return   │             │            │
   │           │    proof    │             │            │
   │           │<────────────│             │            │
   │           │             │             │            │
   │           │ 6. POST /api/signup/midnight           │
   │           │    with proof             │            │
   │           │──────────────────────────>│            │
   │           │             │             │            │
   │           │             │ 7. Build TX │            │
   │           │             │    (escrow  │            │
   │           │             │    + VPN)   │            │
   │           │             │             │            │
   │           │ 8. Unsigned │             │            │
   │           │    TX       │             │            │
   │           │<──────────────────────────│            │
   │           │             │             │            │
   │ 9. Sign   │             │             │            │
   │<──────────│             │             │            │
   │           │             │             │            │
   │ 10. Submit│             │             │            │
   │───────────────────────────────────────────────────>│
   │           │             │             │            │
   │           │             │             │ 11. Verify │
   │           │             │             │     proof  │
   │           │             │             │<───────────│
   │           │             │             │            │
   │ 12. VPN   │             │             │            │
   │     active│             │             │            │
   │<──────────────────────────────────────────────────│
```

### 4.5 Escrow Validation Rules

The escrow validator checks:

1. Midnight payments are enabled in config
2. ZK proof is valid (calls Halo2 verifier)
3. Nullifier has not been used (no existing nullifier token)
4. Nullifier token is minted in this transaction
5. VPN token is minted in this transaction
6. Owner has signed the transaction
7. Selected region is valid
8. Provider receives correct ADA payment
9. Escrow continuing output has updated state

### 4.6 ZK Proof Public Inputs

The Halo2 proof commits to two public inputs:

| Input | Description |
|-------|-------------|
| selection | Pricing tier index (0, 1, or 2) |
| nullifier | 32-byte unique identifier derived from secret_key + sequence + tier |

The proof verifies that the NIGHT payment amount is sufficient for the selected tier without revealing the actual amount paid.

### 4.7 Nullifier Derivation

Nullifiers are derived deterministically to prevent replay:

```
nullifier = persistentHash(secret_key || sequence || tier_index)
```

Where:
- secret_key: User's private key material (kept secret)
- sequence: Incrementing counter per user
- tier_index: Selected pricing tier

This ensures each payment produces a unique nullifier that can only be used once.

### 4.8 Escrow Datum Structures

EscrowConfig (in reference UTxO):

```
EscrowConfig {
  verifier_hash: ByteArray,      # Hash of Halo2 verifier (reserved)
  midnight_enabled: Bool,        # Feature flag
  tier_prices: List<Int>,        # ADA prices per tier (lovelace)
  provider_pkh: VerificationKeyHash,  # Provider public key hash
  vpn_policy_id: PolicyId,       # VPN token policy for validation
}
```

EscrowDatum (in escrow UTxO):

```
EscrowDatum {
  total_ada: Int,                # Total ADA available for payments
  payment_count: Int,            # Number of successful payments
}
```

---

## 5. Security Model

### 5.1 Trust Assumptions

ADA Payments:
- Users trust the Cardano blockchain for transaction finality
- Provider controls pricing via reference data updates
- Audited contracts ensure correct payment validation

Midnight Payments:
- Users trust both Cardano and Midnight blockchains
- Provider pre-funds escrow with ADA
- ZK proof verification is trustless (on-chain)
- Nullifier tracking prevents double-spend

### 5.2 Audit Status

| Component | Auditor | Status |
|-----------|---------|--------|
| vpn.ak | UTxO Company | Audited (Nov 2025) |
| nft.ak | UTxO Company | Audited (Nov 2025) |
| types.ak | UTxO Company | Audited (Nov 2025) |
| utilities.ak (core) | UTxO Company | Audited (Nov 2025) |
| midnight_escrow.ak | - | Requires audit |
| escrow_nft.ak | - | Requires audit |
| escrow_types.ak | - | Requires audit |
| halo2/* | - | Requires audit |
| circuits/ | - | Requires audit |

### 5.3 Attack Vectors and Mitigations

| Attack | Mitigation |
|--------|------------|
| Proof replay | Nullifier tokens prevent reuse of proofs |
| Invalid proof | On-chain Halo2 verification rejects invalid proofs |
| Escrow drain | Only verified proofs can release funds |
| Front-running | Token name derived from consumed UTxO ensures uniqueness |
| Price manipulation | Prices set by provider in reference data |

### 5.4 Failure Modes

| Failure | Impact | Recovery |
|---------|--------|----------|
| Escrow underfunded | Transactions fail to build | Provider deposits more ADA |
| Midnight disabled | API rejects Midnight requests | Use ADA payment instead |
| Invalid region | Transaction rejected on-chain | User selects valid region |
| Expired subscription | User cannot access VPN | User renews or mints new token |

---

## 6. Deployment Architecture

### 6.1 Network Deployments

| Network | Cardano | Midnight | Status |
|---------|---------|----------|--------|
| Testnet | Preprod | Midnight Testnet | Active |
| Mainnet | Mainnet | Midnight Mainnet | Planned |

### 6.2 Deployment Artifacts

```
preprod/
├── reference-nft-policy.json     # Reference NFT policy ID
├── vpn-token-policy.json         # VPN token policy ID
├── validator-address.json        # VPN script address
├── escrow-policy.json            # Escrow validator policy ID
├── escrow-config-nft.json        # Escrow config NFT policy ID
└── escrow-address.json           # Escrow script address

mainnet/
└── (same structure)
```

### 6.3 Reference Data Setup

VPN Reference UTxO contains:

```
VPNReferenceData {
  pricing: [
    Pricing { duration: 2592000000, price: 10000000 },   # 30 days, 10 ADA
    Pricing { duration: 7776000000, price: 25000000 },   # 90 days, 25 ADA
    Pricing { duration: 31536000000, price: 80000000 },  # 365 days, 80 ADA
  ],
  regions: ["us", "eu", "ap"],
}
```

Escrow Config UTxO contains:

```
EscrowConfig {
  verifier_hash: <script_hash>,
  midnight_enabled: true,
  tier_prices: [10000000, 25000000, 80000000],  # Must match VPN pricing
  provider_pkh: <provider_key_hash>,
  vpn_policy_id: <vpn_policy>,
}
```

---

## 7. Integration Points

### 7.1 Frontend Integration

The frontend (vpn-frontend) integrates via:

- Wallet connection: CIP-30 compatible wallets for transaction signing
- API calls: REST endpoints on vpn-indexer for transaction building
- Environment detection: Platform-aware UI for desktop and mobile

### 7.2 Backend Integration

The backend (vpn-indexer) provides:

| Endpoint | Purpose |
|----------|---------|
| POST /api/signup | Build ADA payment transaction |
| POST /api/signup/midnight | Build Midnight payment transaction |
| POST /api/renew | Build renewal transaction |
| GET /api/tiers | Get current pricing tiers |
| GET /api/regions | Get available regions |

### 7.3 Midnight Integration

The Midnight Compact contract (vpn-payment.compact) provides:

- generateNullifier: Creates unique nullifier from user secret
- payForVPN: Processes NIGHT payment and generates ZK proof

### 7.4 Halo2 Circuit Integration

The Rust circuits (circuits/) provide:

| Command | Purpose |
|---------|---------|
| keygen | Generate proving and verification keys |
| prove | Generate ZK proof from witness |
| verify | Verify proof against public inputs |
| export-verifier | Export verification key constants for Aiken |

---

## Appendix A: Type Definitions

### VPN Types (lib/types.ak)

```
type Pricing {
  duration: Int,     # Duration in milliseconds
  price: Int,        # Price in lovelace
}

type VPNDatum {
  VPNReferenceData { pricing: List<Pricing>, regions: List<ByteArray> }
  VPNData { owner: VerificationKeyHash, region: ByteArray, expiration_time: Int }
}

type VPNAction {
  MintVPNAccess { owner, region, selection, tx_ref }
  UpdateReferenceData { pricing, regions }
  ExtendVPNAccess { new_owner, selection }
  BurnVPNAccess
}
```

### Escrow Types (lib/escrow_types.ak)

```
type EscrowConfig {
  verifier_hash: ByteArray,
  midnight_enabled: Bool,
  tier_prices: List<Int>,
  provider_pkh: VerificationKeyHash,
  vpn_policy_id: PolicyId,
}

type EscrowDatum {
  total_ada: Int,
  payment_count: Int,
}

type EscrowSpendAction {
  ReleaseFunds { zk_proof, nullifier, midnight_state_root, selection, owner, region, tx_ref }
  WithdrawExcess { amount }
  DepositFunds
}

type EscrowMintAction {
  MintNullifier { nullifier }
  MintConfigNFT
  Burn
}
```

---

## Appendix B: References

- Aiken Documentation: https://aiken-lang.org/
- Halo2 Book: https://zcash.github.io/halo2/
- Midnight Documentation: https://docs.midnight.network/
- CIP-30 Wallet Standard: https://cips.cardano.org/cips/cip30/
- BLS12-381 Curve: https://hackmd.io/@benjaminion/bls12-381

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-27 | Blink Labs Engineering | Initial version |
