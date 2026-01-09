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
  BurnVPNAccess, ExtendVPNAccess, ExtendVPNAccessWithProof, MintVPNAccess,
  MintVPNAccessWithProof, Pricing, UpdateReferenceData, VPNAction, VPNData,
  VPNDatum, VPNMidnightConfig, VPNReferenceData,
}
use utilities.{derive_nullifier_policy, output_reference_to_tn}
use vpn

const reference_cs = blake2b_224("reference_cs")

const provider_pkh = blake2b_224("provider_pkh")

const provider_stake_pkh =
  Inline(VerificationKey(blake2b_224("provider_stake_pkh")))

const provider_address =
  Address(VerificationKey(provider_pkh), Some(provider_stake_pkh))

//Some(provider_stake_pkh))

const user_pkh = blake2b_224("user_pkh")

const vpn = blake2b_224("vpn")

const vpn_address = Address(Script(vpn), provider_address.stake_credential)

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
    address: vpn_address,
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
    vpn_address,
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
  vpn.vpn.mint(1000, reference_cs, provider_address, redeemer, vpn, tx)
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
      mock_pub_key_output(provider_address, from_lovelace(20)),
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

fn vpn_spend(datum: VPNDatum, redeemer: VPNAction, tx: Transaction) -> Bool {
  vpn.vpn.spend(
    1000,
    reference_cs,
    provider_address,
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
    outputs: [vpn_output(VPNData(user_pkh, "r2", 110))],
    validity_range: after(109),
  }

test extend_vpn_access_succeed1() {
  vpn_spend(
    VPNData(user_pkh, "r2", 110),
    ExtendVPNAccess("", -1),
    extend_vpn_access_succeed_tx,
  )
}

test extend_vpn_access_succeed2() {
  let tx = extend_vpn_access_succeed_tx
  vpn_spend(
    VPNData(user_pkh, "r2", 108),
    ExtendVPNAccess("", 2),
    Transaction {
      ..tx,
      outputs: [
        vpn_output(VPNData(user_pkh, "r2", 139)),
        mock_pub_key_output(provider_address, from_lovelace(50)),
      ],
    },
  )
}

test extend_vpn_access_fail1_signature() fail {
  vpn_spend(
    VPNData(user_pkh, "r2", 110),
    ExtendVPNAccess("", 2),
    Transaction { ..extend_vpn_access_succeed_tx, extra_signatories: [] },
  )
}

test extend_vpn_access_fail2_wrong_token() fail {
  vpn_spend(
    VPNData(user_pkh, "r2", 110),
    ExtendVPNAccess("", 2),
    extend_vpn_access_succeed_tx,
  )
}

test extend_vpn_access_fail3_selection() fail {
  vpn_spend(
    VPNData(user_pkh, "r2", 110),
    ExtendVPNAccess("", 1),
    extend_vpn_access_succeed_tx,
  )
}

test extend_vpn_access_fail4_region() fail {
  vpn_spend(
    VPNData(user_pkh, "r1", 110),
    ExtendVPNAccess("", 2),
    extend_vpn_access_succeed_tx,
  )
}

test burn_access_succeed() {
  vpn_mint(BurnVPNAccess, placeholder)
}

test burn_access_fail1_output() fail {
  vpn_mint(
    BurnVPNAccess,
    Transaction {
      ..placeholder,
      outputs: [vpn_output(VPNData(user_pkh, "r2", 110))],
    },
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
    mint: from_asset(vpn, output_reference_to_tn(mock_utxo_ref("0", 1)), -1),
  }

test burn_vpn_access_succeed1_owner() {
  vpn_spend(
    VPNData(user_pkh, "r2", 110),
    BurnVPNAccess,
    burn_vpn_access_succeed_tx,
  )
}

test burn_vpn_access_succeed2_provider() {
  vpn_spend(
    VPNData(user_pkh, "r2", 110),
    BurnVPNAccess,
    Transaction {
      ..burn_vpn_access_succeed_tx,
      validity_range: after(1111),
      extra_signatories: [provider_pkh],
    },
  )
}

test burn_vpn_access_fail1_signature() fail {
  vpn_spend(VPNData("a", "r2", 110), BurnVPNAccess, burn_vpn_access_succeed_tx)
}

test burn_vpn_access_fail2_deadline() fail {
  vpn_spend(
    VPNData(user_pkh, "r2", 112),
    BurnVPNAccess,
    burn_vpn_access_succeed_tx,
  )
}

// ============================================================================
// Midnight ZK Payment Tests
// ============================================================================

// Midnight config policy derived from reference_cs (must match validator logic)
// The validator uses derive_nullifier_policy(reference_policy_id) for Midnight config
fn get_midnight_config_policy_id() -> ByteArray {
  derive_nullifier_policy(reference_cs)
}

// Mock ZK proof data
const mock_zk_proof = blake2b_256("mock_zk_proof")

const mock_nullifier = blake2b_256("mock_nullifier")

const mock_state_root = blake2b_256("mock_state_root")

// Nullifier policy derived from VPN policy
fn get_nullifier_policy_id() -> ByteArray {
  derive_nullifier_policy(vpn)
}

// Midnight config output for reference input
fn midnight_config_output() -> Output {
  Output {
    address: vpn_address,
    value: create_min_ada_token_value(get_midnight_config_policy_id(), "MidnightConfig", 1),
    datum: InlineDatum(VPNMidnightConfig { verifier_hash: blake2b_256("verifier"), midnight_enabled: True }),
    reference_script: None,
  }
}

const midnight_config_input =
  Input {
    output_reference: mock_utxo_ref("20", 20),
    output: midnight_config_output(),
  }

// Transaction for MintVPNAccessWithProof
const mint_access_with_proof_succeed_tx =
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
    reference_inputs: [nft_input, midnight_config_input],
    outputs: [
      vpn_output(VPNData(user_pkh, "r2", 110)),
      // No payment to provider required - verified via ZK proof
    ],
    mint: add(
      from_asset(vpn, output_reference_to_tn(mock_utxo_ref("0", 1)), 1),
      get_nullifier_policy_id(),
      mock_nullifier,
      1,
    ),
    validity_range: after(100),
    extra_signatories: [user_pkh],
  }

// Note: This test will pass because verify_midnight_payment is a placeholder
// that always returns True. In production, actual Halo2 verification would run.
test mint_access_with_proof_succeed() {
  vpn_mint(
    MintVPNAccessWithProof(
      user_pkh,
      "r2",
      1,
      mock_utxo_ref("0", 1),
      mock_zk_proof,
      mock_nullifier,
      mock_state_root,
    ),
    mint_access_with_proof_succeed_tx,
  )
}

test mint_access_with_proof_fail_wrong_region() fail {
  vpn_mint(
    MintVPNAccessWithProof(
      user_pkh,
      "invalid_region",
      1,
      mock_utxo_ref("0", 1),
      mock_zk_proof,
      mock_nullifier,
      mock_state_root,
    ),
    mint_access_with_proof_succeed_tx,
  )
}

test mint_access_with_proof_fail_missing_nullifier_mint() fail {
  vpn_mint(
    MintVPNAccessWithProof(
      user_pkh,
      "r2",
      1,
      mock_utxo_ref("0", 1),
      mock_zk_proof,
      mock_nullifier,
      mock_state_root,
    ),
    Transaction {
      ..mint_access_with_proof_succeed_tx,
      // Only mint VPN token, not nullifier
      mint: from_asset(vpn, output_reference_to_tn(mock_utxo_ref("0", 1)), 1),
    },
  )
}

test mint_access_with_proof_fail_missing_signature() fail {
  vpn_mint(
    MintVPNAccessWithProof(
      user_pkh,
      "r2",
      1,
      mock_utxo_ref("0", 1),
      mock_zk_proof,
      mock_nullifier,
      mock_state_root,
    ),
    Transaction { ..mint_access_with_proof_succeed_tx, extra_signatories: [] },
  )
}
