use aiken/crypto.{VerificationKeyHash}
use cardano/assets.{AssetName}
use cardano/transaction.{OutputReference}

pub type Pricing {
  duration: Int,
  price: Int,
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
  MintVPNAccess {
    owner: VerificationKeyHash,
    region: ByteArray,
    selection: Int,
    tx_ref: OutputReference,
  }
  UpdateReferenceData { pricing: List<Pricing>, regions: List<ByteArray> }
  ExtendVPNAccess {
    maybe_new_owner: Option<VerificationKeyHash>,
    token_name: AssetName,
    selection: Int,
  }
  BurnVPNAccess(AssetName)
}
