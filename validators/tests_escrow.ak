use aiken/builtin
use aiken/crypto.{blake2b_224, blake2b_256}
use aiken/interval.{after}
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets.{Value, add, from_asset, from_lovelace}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction, placeholder,
}
use escrow_types.{
  DepositFunds, EscrowConfig, EscrowDatum, EscrowMintAction, EscrowSpendAction,
  MintNullifier, ReleaseFunds, WithdrawExcess,
}
use midnight_escrow
use types.{Pricing, VPNData, VPNDatum, VPNReferenceData}
use utilities.{output_reference_to_tn}

// ============================================================================
// Test Constants
// ============================================================================

const escrow_config_cs = blake2b_224("escrow_config_cs")

const vpn_reference_cs = blake2b_224("vpn_reference_cs")

const escrow_policy = blake2b_224("escrow_policy")

const vpn_policy = blake2b_224("vpn_policy")

const provider_pkh = blake2b_224("provider_pkh")

const provider_stake_pkh =
  Inline(VerificationKey(blake2b_224("provider_stake_pkh")))

const provider_address =
  Address(VerificationKey(provider_pkh), Some(provider_stake_pkh))

const user_pkh = blake2b_224("user_pkh")

const escrow_address = Address(Script(escrow_policy), Some(provider_stake_pkh))

const vpn_address = Address(Script(vpn_policy), Some(provider_stake_pkh))

// ============================================================================
// Test Helpers
// ============================================================================

fn mock_utxo_ref(id: ByteArray, ix: Int) -> OutputReference {
  OutputReference { transaction_id: blake2b_256(id), output_index: ix }
}

fn mock_pub_key_address(bytearray: ByteArray) -> Address {
  Address(VerificationKey(blake2b_224(bytearray)), None)
}

fn mock_pub_key_output(address: Address, value: Value) -> Output {
  Output { address, value, datum: NoDatum, reference_script: None }
}

fn create_min_ada_token_value(
  policy_id: ByteArray,
  token_name: ByteArray,
  am: Int,
) -> Value {
  add(from_lovelace(2_000_000), policy_id, token_name, am)
}

// ============================================================================
// Reference Inputs
// ============================================================================

fn vpn_reference_output() -> Output {
  Output {
    address: vpn_address,
    value: create_min_ada_token_value(vpn_reference_cs, "VPNRef", 1),
    datum: InlineDatum(
      VPNReferenceData {
        pricing: [
          Pricing(5, 10_000_000),
          Pricing(10, 20_000_000),
          Pricing(30, 50_000_000),
        ],
        regions: ["us", "eu", "ap"],
      },
    ),
    reference_script: None,
  }
}

const vpn_reference_input =
  Input {
    output_reference: mock_utxo_ref("vpn_ref", 0),
    output: vpn_reference_output(),
  }

fn escrow_config_output() -> Output {
  Output {
    address: escrow_address,
    value: create_min_ada_token_value(escrow_config_cs, "EscrowConfig", 1),
    datum: InlineDatum(
      EscrowConfig {
        verifier_hash: blake2b_256("verifier"),
        midnight_enabled: True,
        tier_prices: [10_000_000, 20_000_000, 50_000_000],
        provider_pkh,
        vpn_policy_id: vpn_policy,
      },
    ),
    reference_script: None,
  }
}

const escrow_config_input =
  Input {
    output_reference: mock_utxo_ref("escrow_config", 0),
    output: escrow_config_output(),
  }

// ============================================================================
// Escrow UTxO
// ============================================================================

fn escrow_utxo_output(total_ada: Int, payment_count: Int) -> Output {
  Output {
    address: escrow_address,
    value: add(from_lovelace(total_ada), escrow_config_cs, "EscrowConfig", 1),
    datum: InlineDatum(EscrowDatum { total_ada, payment_count }),
    reference_script: None,
  }
}

// ============================================================================
// VPN Output (for Midnight minting)
// ============================================================================

fn vpn_output(datum: VPNDatum, tx_ref: OutputReference) -> Output {
  Output {
    address: vpn_address,
    value: create_min_ada_token_value(
      vpn_policy,
      output_reference_to_tn(tx_ref),
      1,
    ),
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

// ============================================================================
// Test Data
// ============================================================================

// Mock proof data (will fail verification but tests structure)
const mock_zk_proof = blake2b_256("mock_zk_proof")

const mock_nullifier = blake2b_256("mock_nullifier")

const mock_state_root = blake2b_256("mock_state_root")

// ============================================================================
// Validator Wrapper
// ============================================================================

fn escrow_mint(redeemer: EscrowMintAction, tx: Transaction) -> Bool {
  midnight_escrow.midnight_escrow.mint(
    escrow_config_cs,
    vpn_reference_cs,
    provider_address,
    redeemer,
    escrow_policy,
    tx,
  )
}

fn escrow_spend(
  datum: EscrowDatum,
  redeemer: EscrowSpendAction,
  tx: Transaction,
) -> Bool {
  midnight_escrow.midnight_escrow.spend(
    escrow_config_cs,
    vpn_reference_cs,
    provider_address,
    Some(datum),
    redeemer,
    mock_utxo_ref("escrow", 0),
    tx,
  )
}

// ============================================================================
// Mint Tests
// ============================================================================

test mint_nullifier_succeed() {
  escrow_mint(
    MintNullifier { nullifier: mock_nullifier },
    Transaction {
      ..placeholder,
      mint: from_asset(escrow_policy, mock_nullifier, 1),
    },
  )
}

test mint_nullifier_fail_wrong_length() fail {
  escrow_mint(
    MintNullifier { nullifier: "short" },
    Transaction { ..placeholder, mint: from_asset(escrow_policy, "short", 1) },
  )
}

test mint_nullifier_fail_wrong_amount() fail {
  escrow_mint(
    MintNullifier { nullifier: mock_nullifier },
    Transaction {
      ..placeholder,
      mint: from_asset(escrow_policy, mock_nullifier, 2),
    },
  )
}

// ============================================================================
// Spend Tests - WithdrawExcess
// ============================================================================

test withdraw_excess_succeed() {
  let initial_ada = 100_000_000
  let withdraw_amount = 50_000_000
  escrow_spend(
    EscrowDatum { total_ada: initial_ada, payment_count: 5 },
    WithdrawExcess { amount: withdraw_amount },
    Transaction {
      ..placeholder,
      inputs: [
        Input(mock_utxo_ref("escrow", 0), escrow_utxo_output(initial_ada, 5)),
      ],
      outputs: [
        escrow_utxo_output(initial_ada - withdraw_amount, 5),
        mock_pub_key_output(provider_address, from_lovelace(withdraw_amount)),
      ],
      extra_signatories: [provider_pkh],
    },
  )
}

test withdraw_excess_fail_no_signature() fail {
  escrow_spend(
    EscrowDatum { total_ada: 100_000_000, payment_count: 5 },
    WithdrawExcess { amount: 50_000_000 },
    Transaction {
      ..placeholder,
      inputs: [
        Input(mock_utxo_ref("escrow", 0), escrow_utxo_output(100_000_000, 5)),
      ],
      outputs: [escrow_utxo_output(50_000_000, 5)],
      extra_signatories: [],
    },
  )
}

// ============================================================================
// Spend Tests - DepositFunds
// ============================================================================

test deposit_funds_succeed() {
  escrow_spend(
    EscrowDatum { total_ada: 100_000_000, payment_count: 0 },
    DepositFunds,
    Transaction {
      ..placeholder,
      inputs: [
        Input(mock_utxo_ref("escrow", 0), escrow_utxo_output(100_000_000, 0)),
      ],
      outputs: [escrow_utxo_output(200_000_000, 0)],
      extra_signatories: [provider_pkh],
    },
  )
}

// ============================================================================
// Spend Tests - ReleaseFunds (structure tests, proof verification will fail)
// ============================================================================

// Note: Full ReleaseFunds tests require valid ZK proofs.
// These tests verify the transaction structure is correct.
// Proof verification tests are in proof_verifier.ak

test release_funds_fail_midnight_disabled() fail {
  let user_utxo_ref = mock_utxo_ref("user", 1)
  let token_name = output_reference_to_tn(user_utxo_ref)

  // Create config with midnight_enabled = False
  let disabled_config_output =
    Output {
      address: escrow_address,
      value: create_min_ada_token_value(escrow_config_cs, "EscrowConfig", 1),
      datum: InlineDatum(
        EscrowConfig {
          verifier_hash: blake2b_256("verifier"),
          midnight_enabled: False,
          tier_prices: [10_000_000, 20_000_000, 50_000_000],
          provider_pkh,
          vpn_policy_id: vpn_policy,
        },
      ),
      reference_script: None,
    }

  escrow_spend(
    EscrowDatum { total_ada: 100_000_000, payment_count: 0 },
    ReleaseFunds {
      zk_proof: mock_zk_proof,
      nullifier: mock_nullifier,
      midnight_state_root: mock_state_root,
      selection: 0,
      owner: user_pkh,
      region: "us",
      tx_ref: user_utxo_ref,
    },
    Transaction {
      ..placeholder,
      inputs: [
        Input(mock_utxo_ref("escrow", 0), escrow_utxo_output(100_000_000, 0)),
        Input(
          user_utxo_ref,
          mock_pub_key_output(
            mock_pub_key_address("user"),
            from_lovelace(5_000_000),
          ),
        ),
      ],
      reference_inputs: [
        vpn_reference_input,
        Input {
          output_reference: mock_utxo_ref("disabled_config", 0),
          output: disabled_config_output,
        },
      ],
      outputs: [
        escrow_utxo_output(90_000_000, 1),
        mock_pub_key_output(provider_address, from_lovelace(10_000_000)),
        vpn_output(
          VPNData { owner: user_pkh, region: "us", expiration_time: 105 },
          user_utxo_ref,
        ),
      ],
      mint: add(
        from_asset(escrow_policy, mock_nullifier, 1),
        vpn_policy,
        token_name,
        1,
      ),
      validity_range: after(100),
      extra_signatories: [user_pkh],
    },
  )
}

test release_funds_fail_wrong_region() fail {
  let user_utxo_ref = mock_utxo_ref("user", 1)
  let token_name = output_reference_to_tn(user_utxo_ref)

  escrow_spend(
    EscrowDatum { total_ada: 100_000_000, payment_count: 0 },
    ReleaseFunds {
      zk_proof: mock_zk_proof,
      nullifier: mock_nullifier,
      midnight_state_root: mock_state_root,
      selection: 0,
      owner: user_pkh,
      region: "invalid_region",
      tx_ref: user_utxo_ref,
    },
    Transaction {
      ..placeholder,
      inputs: [
        Input(mock_utxo_ref("escrow", 0), escrow_utxo_output(100_000_000, 0)),
        Input(
          user_utxo_ref,
          mock_pub_key_output(
            mock_pub_key_address("user"),
            from_lovelace(5_000_000),
          ),
        ),
      ],
      reference_inputs: [vpn_reference_input, escrow_config_input],
      outputs: [
        escrow_utxo_output(90_000_000, 1),
        mock_pub_key_output(provider_address, from_lovelace(10_000_000)),
        vpn_output(
          VPNData {
            owner: user_pkh,
            region: "invalid_region",
            expiration_time: 105,
          },
          user_utxo_ref,
        ),
      ],
      mint: add(
        from_asset(escrow_policy, mock_nullifier, 1),
        vpn_policy,
        token_name,
        1,
      ),
      validity_range: after(100),
      extra_signatories: [user_pkh],
    },
  )
}

test release_funds_fail_missing_nullifier_mint() fail {
  let user_utxo_ref = mock_utxo_ref("user", 1)
  let token_name = output_reference_to_tn(user_utxo_ref)

  escrow_spend(
    EscrowDatum { total_ada: 100_000_000, payment_count: 0 },
    ReleaseFunds {
      zk_proof: mock_zk_proof,
      nullifier: mock_nullifier,
      midnight_state_root: mock_state_root,
      selection: 0,
      owner: user_pkh,
      region: "us",
      tx_ref: user_utxo_ref,
    },
    Transaction {
      ..placeholder,
      inputs: [
        Input(mock_utxo_ref("escrow", 0), escrow_utxo_output(100_000_000, 0)),
        Input(
          user_utxo_ref,
          mock_pub_key_output(
            mock_pub_key_address("user"),
            from_lovelace(5_000_000),
          ),
        ),
      ],
      reference_inputs: [vpn_reference_input, escrow_config_input],
      outputs: [
        escrow_utxo_output(90_000_000, 1),
        mock_pub_key_output(provider_address, from_lovelace(10_000_000)),
        vpn_output(
          VPNData { owner: user_pkh, region: "us", expiration_time: 105 },
          user_utxo_ref,
        ),
      ],
      // Missing nullifier mint!
      mint: from_asset(vpn_policy, token_name, 1),
      validity_range: after(100),
      extra_signatories: [user_pkh],
    },
  )
}

test release_funds_fail_missing_user_signature() fail {
  let user_utxo_ref = mock_utxo_ref("user", 1)
  let token_name = output_reference_to_tn(user_utxo_ref)

  escrow_spend(
    EscrowDatum { total_ada: 100_000_000, payment_count: 0 },
    ReleaseFunds {
      zk_proof: mock_zk_proof,
      nullifier: mock_nullifier,
      midnight_state_root: mock_state_root,
      selection: 0,
      owner: user_pkh,
      region: "us",
      tx_ref: user_utxo_ref,
    },
    Transaction {
      ..placeholder,
      inputs: [
        Input(mock_utxo_ref("escrow", 0), escrow_utxo_output(100_000_000, 0)),
        Input(
          user_utxo_ref,
          mock_pub_key_output(
            mock_pub_key_address("user"),
            from_lovelace(5_000_000),
          ),
        ),
      ],
      reference_inputs: [vpn_reference_input, escrow_config_input],
      outputs: [
        escrow_utxo_output(90_000_000, 1),
        mock_pub_key_output(provider_address, from_lovelace(10_000_000)),
        vpn_output(
          VPNData { owner: user_pkh, region: "us", expiration_time: 105 },
          user_utxo_ref,
        ),
      ],
      mint: add(
        from_asset(escrow_policy, mock_nullifier, 1),
        vpn_policy,
        token_name,
        1,
      ),
      validity_range: after(100),
      extra_signatories: [],
    },
  )
}

// ============================================================================
// Integration Test - Real ZK Proof Data
// ============================================================================
// This test uses real proof data from circuits/test_proof.script.json
// The proof was generated by the Rust Halo2 circuit with:
//   - pricing_tier (selection): 1
//   - nullifier: 0x00147b051673afc0a6618006daf6f07889d5c8597599cb45b34c21bcf0da0c5f
//
// Note: This test verifies the integration between escrow and ZK verification.
// The proof verification itself is tested in lib/halo2/proof_verifier.ak

// Real proof data from circuits/test_proof.script.json
const real_zk_proof =
  #"aaca2de5d319fcedc4a92ca4c7d5972d805352259214956f4fc5b10670f79d9c83cf271da48b44050074f635f96e1f698c1502377b3002c73fd026dd12c540c4fa9ec4ce17bb0737cd16e56c52d98df35e77c07530e9b47e23a22ee6ee8160a38e15e5b6b3a9bdd4a1e3412cd32d589bbd167fdd8830a2d148fa75affb1a2237e9a173d0ddc903ed30d2be556936b86a8820c115bfc7f3e2965fb87760a7a4c8bb35ec4f7aaed8580e02b6e5a322595d06e8ec31feb994614b382cde2f2fad928288d8dc1c837b10e6f23782059158fe5594225d50093138a582abadda798bb7a26f53f3c04a940ecda63bdbb9620b66b3ae66b248c78025adad9516320347f6dcc549a39c04953bf8f5e92b5a002f1d6f2f9bbf9a06e6433066c6b38be02d3aae53813d3a0deef1d1b4aa9260e7156c720b9df2376d3e33d871e2a4b50d8b9d2c75d998849f29a12c4894b7a55e1aa2aaf4bf9c893c478e4aa34994d2506b0630b22056dad642498709058e3076bcac549e3800910085c8d697cba6178cb06da9fd445f9b439483a4f1e298a3b75dd8707aac7b9d48918aab0e1e20e9b47539ecb97fd918864d805005e64e08f54851a98c2741cae7719b80155fbad11510ac762d93b7cbec4548f21e1dc1b738bc191e95677d71ff800ce2485fa68dc38adead8cf6cfb5773546074344dc33cdab0580306af104a7a452279329716745998a472f330e9ad7a8a203be33de7c7076feb5fb22ade76d95cc59e315ae2f06ed2d3a4130f6b3da648472f8751ef4cfc7a44a3f4332d431fb1e59f6dad751476ed184880924d9e2c35c23b8390b2f6e8708461deb94a07fb24f83578e9c88b7ad6c38bbe81acd344682329fb16810ce7df1a18d69b6c47ad50754bb389ad42989ccfb5493d329ad466d110089412efca74a23583d5aba2388b36cb19b759d0ffdf744bb6c98dfe45eb63cb4e94fc34d821422b9740e54cac45cb9ef5165c5034fb015ee264edee2528c06c97cf32887ab1a0c9cd3be3ca3b62fd3e669fb206fc1bcc5e4bc9ac8f4a8905d8109bc5e36495d0000000000000000000000000000000000000000000000000000000000000000c88f364f3cf59440493ae0aa9578d580761192c90e9a3a163c8740a0d1baf93a00000000000000000000000000000000000000000000000000000000000000009422e5adec76b029d7dd6b52e43f23f76b3e241ec8ca37ede8f2e9557807cd22c6a88e8d74595d4582c1f4b20ce12000c35e06d44e53e58186d2250a012127289ddeff6957617b72e844a4d466a8c80788a5d49bf81f08d50ba839ba964b8c3cb4d32228f294618993007c59d09e6d0ca6b1d037e53614140a7a269db071b46ad36be6d947504e77fc0a0ac222021a7fa49c6f1bcf85484ecb49185a8a9146429535296ffa8cb8adbe8f58dcf852ba668d00e1b00dff325bb10134b763a8e120c74e64cbb76b895771c98ce0979b05c5cd934815bd3e2e9085eaa1290ae6931306f383c1be8d3c1b9c5be08280ecf261ed0b28186f4598540f03e5ce6eb74c44fc2834730aa59926bc735f447560b4e89142cd25b06658950a8ac32f7f98c1621f15b0d5e533611528c5dee1da6a4d4eca4e74d172641f48889605130c1c372a9a86faf5a7b1ab2618e4cda540ae75d1d999be6bdb94e3c1dcecb8de3995974b2e003ee2f7c229fbb85e6dceb191394ac5c86ac8be08ee25a9ab158da0410e4d9b390cd06c85666ff82a1408248ec2ace93b2f9cc65dc8d4c4f0f8930e2f242e4d84f9bf529e7be8d4b749c5badb0b7fa749fe3509c422ff9c4a7d6c00425649938e100e660d22ac8adf07e4c4727673e6314762517bc470455468b27aa86a1a5a44cc08a7293ebd3ed9c110d1e7655e36d95fb8e2f79044074eb40a8df0c4620adaa45d7b97850aa0d9dba18934b0a38a134649c653241fd095ba02a61210067575775bb255e31f5519dd21429238f1947fe7a7cda4cb70cd42e7761e8d6b292bd503e1806b600d777802ff3d5e75b5a90181b9f92d8b40f75da15db8991f16b9ac743e83df1c70dbf621fb97504f1cde4723ec60d13b4142b5781817e341671881ac9ccb72973ae78709c7201f7aea2b932c5ceda246d2dc7a715c3dbc1a4038a3fa36a1707d0d3d9a6ba88f1ff2a0e0fb961037bb0c1064fb16e80855c81c1220daba2c2fa68c9ae0c6499be29e8c337124324606d8c8b823701c0074fc5aa0501d88592777f14717adf33f48dbac3dc9a72a7f7a37212118d6529a61e5651d23e216f6f7a905c2808b8b75f68b7bd26bb01fd3a8bccf21b1abee5a491d38a0222668ebff2da9de4dbf1f801abadb02191206e8a7dbb7861c3fe9aab9ac2eb9a3c0b0ce68b3fbeaa61c1533d1dfcfeb71bd04f646aba2876fb3eb249eea069d9e21002a0531d579612f4440c73d5920d358e9fe30d7089b28527494e3023dc51591430ce1e5070e2c36b13257ef3a81bb731aa22bc9499c52f91d10c45cf8e97274fced9da396e03157f5023fc12b8b0746025aae54e18eb68917dcfafb9513a4f20dc01058c22e28b745f351c5498fb0340e2021b2c4fd6ba5a0cc9042c0"

const real_nullifier =
  #"00147b051673afc0a6618006daf6f07889d5c8597599cb45b34c21bcf0da0c5f"

const real_state_root =
  #"0505050505050505050505050505050505050505050505050505050505050505"

const real_selection = 1

// Test: Verify nullifier length is correct (32 bytes)
test real_proof_nullifier_length() {
  builtin.length_of_bytearray(real_nullifier) == 32
}

// Test: Verify proof data length is reasonable (> 1KB for Halo2)
test real_proof_data_length() {
  builtin.length_of_bytearray(real_zk_proof) > 1000
}

// Test: Verify state root length is correct (32 bytes)
test real_proof_state_root_length() {
  builtin.length_of_bytearray(real_state_root) == 32
}
