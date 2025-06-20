use aiken/crypto.{VerificationKeyHash}
use cardano/assets.{AssetName}

pub type VPNDatum {
  VPNReferenceData { pricing: Pairs<Int, Int>, regions: List<ByteArray> }
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
  }
  UpdateReferenceData { pricing: Pairs<Int, Int>, regions: List<ByteArray> }
  ExtendVPNAccess {
    maybe_new_owner: Option<VerificationKeyHash>,
    token_name: AssetName,
    selection: Int,
  }
  BurnVPNAccess
}
