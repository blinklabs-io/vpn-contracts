use aiken/crypto.{blake2b_224, blake2b_256}
use aiken/interval.{after}
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets.{Value, add, from_asset, from_lovelace}
use cardano/transaction.{
  Datum, InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
  placeholder,
}
use nft
use types.{
  BurnVPNAccess, ExtendVPNAccess, MintVPNAccess, Pricing, UpdateReferenceData,
  VPNAction, VPNData, VPNDatum, VPNReferenceData,
}
use utilities.{output_reference_to_tn}
use vpn

const reference_cs = blake2b_224("reference_cs")

const provider_pkh = blake2b_224("provider_pkh")

const provider_stake_pkh =
  Inline(VerificationKey(blake2b_224("provider_stake_pkh")))

const user_pkh = blake2b_224("user_pkh")

const vpn = blake2b_224("vpn")

fn mock_utxo_ref(id: ByteArray, ix: Int) -> OutputReference {
  OutputReference { transaction_id: blake2b_256(id), output_index: ix }
}

fn mock_pub_key_address(bytearray: ByteArray) -> Address {
  Address(VerificationKey(blake2b_224(bytearray)), None)
}

fn mock_script_output(address: Address, value: Value, datum: Datum) -> Output {
  Output { address, value, datum, reference_script: None }
}

fn create_min_ada_token_value(
  policy_id: ByteArray,
  token_name: ByteArray,
  am: Int,
) -> Value {
  add(from_lovelace(2_000_000), policy_id, token_name, am)
}

/// Create an output with just address and value.
fn mock_pub_key_output(address: Address, value: Value) -> Output {
  mock_script_output(address, value, NoDatum)
}

fn nft_output(datum: VPNDatum) -> Output {
  Output {
    address: Address(Script(vpn), Some(provider_stake_pkh)),
    value: create_min_ada_token_value(reference_cs, "NFT", 1),
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

const nft_input =
  Input {
    output_reference: mock_utxo_ref("10", 10),
    output: nft_output(
      VPNReferenceData {
        pricing: [Pricing(5, 10), Pricing(10, 20), Pricing(30, 50)],
        regions: ["r1", "r2", "r3"],
      },
    ),
  }

fn vpn_output(datum: VPNDatum) -> Output {
  mock_script_output(
    Address(Script(vpn), Some(provider_stake_pkh)),
    create_min_ada_token_value(
      vpn,
      output_reference_to_tn(mock_utxo_ref("0", 1)),
      1,
    ),
    InlineDatum(datum),
  )
}

test mint_nft() {
  nft.nft.mint(
    mock_utxo_ref("0", 0),
    "provider",
    reference_cs,
    Transaction {
      ..placeholder,
      inputs: [
        Input(
          mock_utxo_ref("0", 0),
          mock_pub_key_output(mock_pub_key_address("a"), from_lovelace(5)),
        ),
      ],
      mint: from_asset(reference_cs, "provider", 1),
    },
  )
}

test burn_nft() {
  nft.nft.mint(
    mock_utxo_ref("0", 0),
    "provider",
    reference_cs,
    Transaction {
      ..placeholder,
      mint: from_asset(reference_cs, "provider", -1),
    },
  )
}

fn vpn_mint(redeemer: VPNAction, tx: Transaction) -> Bool {
  vpn.vpn.mint(
    1000,
    reference_cs,
    provider_pkh,
    provider_stake_pkh,
    redeemer,
    vpn,
    tx,
  )
}

const mint_acceess_succeed_tx =
  Transaction {
    ..placeholder,
    inputs: [
      Input(
        mock_utxo_ref("0", 1),
        mock_pub_key_output(
          mock_pub_key_address("user"),
          from_lovelace(2000000),
        ),
      ),
    ],
    reference_inputs: [nft_input],
    outputs: [
      vpn_output(VPNData(user_pkh, "r2", 110)),
      mock_pub_key_output(
        Address(VerificationKey(provider_pkh), Some(provider_stake_pkh)),
        from_lovelace(20),
      ),
    ],
    mint: from_asset(vpn, output_reference_to_tn(mock_utxo_ref("0", 1)), 1),
    validity_range: after(100),
    extra_signatories: [user_pkh],
  }

test mint_access_succeed() {
  vpn_mint(
    MintVPNAccess(user_pkh, "r2", 1, mock_utxo_ref("0", 1)),
    mint_acceess_succeed_tx,
  )
}

test mint_access_fail1_region() fail {
  vpn_mint(
    MintVPNAccess(user_pkh, "r4", 1, mock_utxo_ref("0", 1)),
    mint_acceess_succeed_tx,
  )
}

test mint_access_fail2_selection() fail {
  vpn_mint(
    MintVPNAccess(user_pkh, "r2", 2, mock_utxo_ref("0", 1)),
    mint_acceess_succeed_tx,
  )
}

test mint_access_fail3_tx_ref() fail {
  vpn_mint(
    MintVPNAccess(user_pkh, "r2", 1, mock_utxo_ref("0", 2)),
    mint_acceess_succeed_tx,
  )
}

test mint_access_fail4_signature() fail {
  vpn_mint(
    MintVPNAccess("a", "r2", 1, mock_utxo_ref("0", 1)),
    mint_acceess_succeed_tx,
  )
}

test mint_access_fail5_ref_input() fail {
  vpn_mint(
    MintVPNAccess(user_pkh, "r2", 1, mock_utxo_ref("0", 1)),
    Transaction { ..mint_acceess_succeed_tx, reference_inputs: [] },
  )
}

test burn_access_succeed() {
  vpn_mint(
    BurnVPNAccess(""),
    Transaction { ..placeholder, mint: from_asset(vpn, "", -1) },
  )
}

test burn_access_fail1_mint() fail {
  vpn_mint(
    BurnVPNAccess(""),
    Transaction { ..placeholder, mint: from_asset(vpn, "", 1) },
  )
}

test burn_access_fail2_burn_mint() fail {
  vpn_mint(
    BurnVPNAccess(""),
    Transaction {
      ..placeholder,
      mint: add(from_asset(vpn, "", -1), vpn, "a", 1),
    },
  )
}

fn vpn_spend(datum: VPNDatum, redeemer: VPNAction, tx: Transaction) -> Bool {
  vpn.vpn.spend(
    1000,
    reference_cs,
    provider_pkh,
    provider_stake_pkh,
    Some(datum),
    redeemer,
    mock_utxo_ref("0", 0),
    tx,
  )
}

const update_reference_data_succeed_tx =
  Transaction {
    ..placeholder,
    inputs: [Input { ..nft_input, output_reference: mock_utxo_ref("0", 0) }],
    outputs: [
      nft_output(
        VPNReferenceData {
          pricing: [Pricing(6, 11), Pricing(11, 21), Pricing(31, 51)],
          regions: ["r4", "r5", "r6"],
        },
      ),
    ],
    extra_signatories: [provider_pkh],
  }

const spend_burn_succeed_tx =
  Transaction {
    ..placeholder,
    inputs: [Input { ..nft_input, output_reference: mock_utxo_ref("0", 0) }],
    mint: from_asset(reference_cs, "provider", -1),
    extra_signatories: [provider_pkh],
  }

test update_reference_data_burn_nft_succeed() {
  vpn_spend(
    VPNReferenceData {
      pricing: [Pricing(5, 10), Pricing(10, 20), Pricing(30, 50)],
      regions: ["r1", "r2", "r3"],
    },
    UpdateReferenceData([], []),
    spend_burn_succeed_tx,
  ) && nft.nft.mint(
    mock_utxo_ref("0", 0),
    "provider",
    reference_cs,
    spend_burn_succeed_tx,
  )
}

test update_reference_data_succeed() {
  vpn_spend(
    VPNReferenceData {
      pricing: [Pricing(5, 10), Pricing(10, 20), Pricing(30, 50)],
      regions: ["r1", "r2", "r3"],
    },
    UpdateReferenceData(
      [Pricing(6, 11), Pricing(11, 21), Pricing(31, 51)],
      ["r4", "r5", "r6"],
    ),
    update_reference_data_succeed_tx,
  )
}

test update_reference_data_fail1_signature() fail {
  vpn_spend(
    VPNReferenceData {
      pricing: [Pricing(5, 10), Pricing(10, 20), Pricing(30, 50)],
      regions: ["r1", "r2", "r3"],
    },
    UpdateReferenceData(
      [Pricing(6, 11), Pricing(11, 21), Pricing(31, 51)],
      ["r4", "r5", "r6"],
    ),
    Transaction { ..update_reference_data_succeed_tx, extra_signatories: [] },
  )
}

test update_reference_data_fail2_datum() fail {
  vpn_spend(
    VPNReferenceData {
      pricing: [Pricing(5, 10), Pricing(10, 20), Pricing(30, 50)],
      regions: ["r1", "r2", "r3"],
    },
    UpdateReferenceData([], []),
    update_reference_data_succeed_tx,
  )
}

const extend_vpn_access_succeed_tx =
  Transaction {
    ..placeholder,
    inputs: [
      Input(mock_utxo_ref("0", 0), vpn_output(VPNData(user_pkh, "r2", 110))),
    ],
    reference_inputs: [nft_input],
    outputs: [
      vpn_output(VPNData(user_pkh, "r2", 139)),
      mock_pub_key_output(
        Address(VerificationKey(provider_pkh), Some(provider_stake_pkh)),
        from_lovelace(50),
      ),
    ],
    validity_range: after(109),
    extra_signatories: [user_pkh],
  }

test extend_vpn_access_succeed() {
  vpn_spend(
    VPNData(user_pkh, "r2", 110),
    ExtendVPNAccess(None, output_reference_to_tn(mock_utxo_ref("0", 1)), 2),
    extend_vpn_access_succeed_tx,
  )
}

test extend_vpn_access_fail1_signature() fail {
  vpn_spend(
    VPNData(user_pkh, "r2", 110),
    ExtendVPNAccess(None, output_reference_to_tn(mock_utxo_ref("0", 1)), 2),
    Transaction { ..extend_vpn_access_succeed_tx, extra_signatories: [] },
  )
}

test extend_vpn_access_fail2_wrong_token() fail {
  vpn_spend(
    VPNData(user_pkh, "r2", 110),
    ExtendVPNAccess(None, output_reference_to_tn(mock_utxo_ref("1", 1)), 2),
    extend_vpn_access_succeed_tx,
  )
}

test extend_vpn_access_fail3_selection() fail {
  vpn_spend(
    VPNData(user_pkh, "r2", 110),
    ExtendVPNAccess(None, output_reference_to_tn(mock_utxo_ref("0", 1)), 1),
    extend_vpn_access_succeed_tx,
  )
}

test extend_vpn_access_fail4_region() fail {
  vpn_spend(
    VPNData(user_pkh, "r1", 110),
    ExtendVPNAccess(None, output_reference_to_tn(mock_utxo_ref("0", 1)), 2),
    extend_vpn_access_succeed_tx,
  )
}

const burn_vpn_access_succeed_tx =
  Transaction {
    ..placeholder,
    inputs: [
      Input(mock_utxo_ref("0", 0), vpn_output(VPNData(user_pkh, "r2", 110))),
    ],
    validity_range: after(111),
    extra_signatories: [user_pkh],
  }

test burn_vpn_access_succeed() {
  vpn_spend(
    VPNData(user_pkh, "r2", 110),
    BurnVPNAccess(output_reference_to_tn(mock_utxo_ref("0", 1))),
    burn_vpn_access_succeed_tx,
  )
}

test burn_vpn_access_fail1_signature() fail {
  vpn_spend(
    VPNData("a", "r2", 110),
    BurnVPNAccess(output_reference_to_tn(mock_utxo_ref("0", 1))),
    burn_vpn_access_succeed_tx,
  )
}

test burn_vpn_access_fail2_deadline() fail {
  vpn_spend(
    VPNData(user_pkh, "r2", 112),
    BurnVPNAccess(output_reference_to_tn(mock_utxo_ref("0", 1))),
    burn_vpn_access_succeed_tx,
  )
}

test burn_vpn_access_fail3_tn() fail {
  vpn_spend(
    VPNData(user_pkh, "r2", 110),
    BurnVPNAccess(output_reference_to_tn(mock_utxo_ref("0", 0))),
    burn_vpn_access_succeed_tx,
  )
}
