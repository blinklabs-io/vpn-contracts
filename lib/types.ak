use aiken/crypto.{VerificationKeyHash}
use cardano/transaction.{OutputReference}

pub type Pricing {
  duration: Int,
  price: Int,
}

/// Midnight ZK payment configuration (stored in separate reference input)
/// Enables Midnight payments without modifying existing VPNReferenceData
pub type VPNMidnightConfig {
  verifier_hash: ByteArray,
  midnight_enabled: Bool,
}

pub type VPNDatum {
  VPNReferenceData { pricing: List<Pricing>, regions: List<ByteArray> }
  VPNData {
    owner: VerificationKeyHash,
    region: ByteArray,
    expiration_time: Int,
  }
}

pub type VPNAction {
  // Constructor 0: Standard minting with direct ADA payment
  MintVPNAccess {
    owner: VerificationKeyHash,
    region: ByteArray,
    selection: Int,
    tx_ref: OutputReference,
  }
  // Constructor 1: Update reference data (provider only)
  UpdateReferenceData { pricing: List<Pricing>, regions: List<ByteArray> }
  // Constructor 2: Extend/renew VPN access with direct ADA payment
  ExtendVPNAccess { new_owner: VerificationKeyHash, selection: Int }
  // Constructor 3: Burn VPN access token
  BurnVPNAccess
  // Constructor 4: Mint with Midnight ZK proof (no direct ADA payment)
  MintVPNAccessWithProof {
    owner: VerificationKeyHash,
    region: ByteArray,
    selection: Int,
    tx_ref: OutputReference,
    zk_proof: ByteArray,
    nullifier: ByteArray,
    midnight_state_root: ByteArray,
  }
  // Constructor 5: Extend with Midnight ZK proof (no direct ADA payment)
  ExtendVPNAccessWithProof {
    new_owner: VerificationKeyHash,
    selection: Int,
    zk_proof: ByteArray,
    nullifier: ByteArray,
    midnight_state_root: ByteArray,
  }
}
