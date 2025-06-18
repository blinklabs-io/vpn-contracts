use cardano/address.{Address}

pub type VPNDatum {
  VPNReferenceData { pricing: Pairs<Int, Int>, regions: List<ByteArray> }
  VPNData { owner: Address, region: ByteArray, expiration_time: Int }
}

pub type VPNAction {
  MintVPNAccess { owner: Address, region: ByteArray, selection: Int }
  UpdateReferenceData
  ExtendVPNAccess
  Reimburse
  UnlockPayment
  BurnVPNAccess
}
