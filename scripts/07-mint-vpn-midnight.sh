#!/bin/bash
#
# Mint VPN Access Token with Midnight ZK Proof
#
# This script mints a new VPN access token using a ZK proof from Midnight
# instead of a direct ADA payment. The proof must be obtained from a
# Midnight payment transaction first.
#
# Usage: ./07-mint-vpn-midnight.sh <user> <proof_file>
#
# Arguments:
#   user       - User wallet name (must have keys in wallets/)
#   proof_file - Path to JSON file containing Midnight proof data
#
# Proof file format:
# {
#   "zk_proof": "<hex-encoded proof bytes>",
#   "nullifier": "<hex-encoded nullifier>",
#   "state_root": "<hex-encoded midnight state root>",
#   "selection": <pricing tier index>,
#   "region": "<hex-encoded region>"
# }
#

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <user> <proof_file>"
    echo ""
    echo "Arguments:"
    echo "  user       - User wallet name"
    echo "  proof_file - Path to Midnight proof JSON file"
    exit 1
fi

USER=$1
PROOF_FILE=$2

source env.sh
FILE_NAME="vpn-access-midnight"

# Validate proof file exists
if [ ! -f "$PROOF_FILE" ]; then
    echo "Error: Proof file not found: $PROOF_FILE"
    exit 1
fi

# Parse proof data from file
ZK_PROOF=$(jq -r '.zk_proof' "$PROOF_FILE")
NULLIFIER=$(jq -r '.nullifier' "$PROOF_FILE")
STATE_ROOT=$(jq -r '.state_root' "$PROOF_FILE")
SELECTION=$(jq -r '.selection' "$PROOF_FILE")
REGION=$(jq -r '.region' "$PROOF_FILE")

# Validate proof fields
if [ -z "$ZK_PROOF" ] || [ "$ZK_PROOF" = "null" ]; then
    echo "Error: Missing zk_proof in proof file"
    exit 1
fi
if [ -z "$NULLIFIER" ] || [ "$NULLIFIER" = "null" ]; then
    echo "Error: Missing nullifier in proof file"
    exit 1
fi
if [ -z "$STATE_ROOT" ] || [ "$STATE_ROOT" = "null" ]; then
    echo "Error: Missing state_root in proof file"
    exit 1
fi

echo "=== Minting VPN Access with Midnight Proof ==="
echo "User: $USER"
echo "Selection: $SELECTION"
echo "Region: $REGION"
echo "Nullifier: ${NULLIFIER:0:16}..."

# Get pricing info (for duration calculation)
# Default durations matching pricing tiers
case $SELECTION in
    0) duration=3600000 ;;      # 1 hour
    1) duration=259200000 ;;    # 3 days
    2) duration=31536000000 ;;  # 1 year
    *) duration=259200000 ;;    # default 3 days
esac

# Get addresses and UTxOs
USER_ADDR=$(cat $WALLET_PATH/$USER.addr)
UTXO_IN_ADA=$(get_address_biggest_lovelace $USER_ADDR)
echo "UTXO_IN_ADA: $UTXO_IN_ADA"

VPN_ADDR=$(cat $VALIDATOR_PATH/vpn.addr)
NFT_CS=$(cardano-cli hash script --script-file $VALIDATOR_PATH/nft.plutus)
echo "NFT_CS: $NFT_CS"

# Get VPN reference data UTxO
UTXO_VPN_REF_DATA=$(get_UTxO_by_token $VPN_ADDR $NFT_CS.70726f7669646572)
echo "UTXO_VPN_REF_DATA: $UTXO_VPN_REF_DATA"

# Get Midnight config UTxO
MIDNIGHT_CONFIG_CS=$(derive_midnight_config_policy $NFT_CS)
echo "MIDNIGHT_CONFIG_CS: $MIDNIGHT_CONFIG_CS"
UTXO_MIDNIGHT_CONFIG=$(get_UTxO_by_token $VPN_ADDR $MIDNIGHT_CONFIG_CS.4d69646e69676874436f6e666967)
if [ -z "$UTXO_MIDNIGHT_CONFIG" ]; then
    echo "Error: Midnight config not found. Make sure Midnight is enabled for this VPN contract."
    exit 1
fi
echo "UTXO_MIDNIGHT_CONFIG: $UTXO_MIDNIGHT_CONFIG"

# Get VPN policy ID
VPN_CS=$(cardano-cli hash script --script-file $VALIDATOR_PATH/vpn.plutus)
echo "VPN_CS: $VPN_CS"

# Calculate token name from consumed UTxO
TN=$(blake2b_256_txoutref $UTXO_IN_ADA)
echo "TN: $TN"

# Get nullifier policy ID
NULLIFIER_CS=$(derive_nullifier_policy $VPN_CS)
echo "NULLIFIER_CS: $NULLIFIER_CS"

# Get user's payment key hash
USER_PKH=$(cardano-cli address key-hash --payment-verification-key-file $WALLET_PATH/$USER.vkey)

# Calculate validity range
cur_time=$(date -u --date="now - 400 seconds" +"%Y-%m-%dT%H:%M:%SZ")
echo "cur_time: $cur_time"
cur_slot=$(cardano-cli query slot-number "$cur_time" ${TESTNET_MAGIC})
EX_UTC=$(( $(date -u --date="$cur_time" +%s%3N) + $duration ))
echo "EX_UTC: $EX_UTC"

# Generate VPN datum
vpn_datum=$(generate_vpn_data_json $USER_PKH $REGION $EX_UTC)
DATUM_PATH=$DATUMS_PATH/"$USER"_vpn_data_midnight.json
echo $vpn_datum > $DATUM_PATH
echo "VPN Datum:"
cat $DATUM_PATH

# Generate redeemer with proof
redeemer=$(generate_vpn_access_with_proof_redeemer_json \
    $USER_PKH \
    $REGION \
    $SELECTION \
    $UTXO_IN_ADA \
    $ZK_PROOF \
    $NULLIFIER \
    $STATE_ROOT)
REDEEMER_PATH=$REDEEMERS_PATH/"$USER"_mint_midnight.json
echo $redeemer > $REDEEMER_PATH
echo "Redeemer saved to: $REDEEMER_PATH"

# Build transaction
# Note: We mint both the VPN token AND the nullifier token
echo ""
echo "Building transaction..."
cardano-cli conway transaction build \
    ${TESTNET_MAGIC} \
    --tx-in-collateral ${UTXO_IN_ADA} \
    --tx-in ${UTXO_IN_ADA} \
    --read-only-tx-in-reference $UTXO_VPN_REF_DATA \
    --read-only-tx-in-reference $UTXO_MIDNIGHT_CONFIG \
    --mint "1 $VPN_CS.$TN + 1 $NULLIFIER_CS.$NULLIFIER" \
    --mint-tx-in-reference $VPN_TX_REF \
    --mint-plutus-script-v3 \
    --mint-reference-tx-in-redeemer-file $REDEEMER_PATH \
    --policy-id $VPN_CS \
    --tx-out $VPN_ADDR+2000000+"1 $VPN_CS.$TN" \
    --tx-out-inline-datum-file $DATUM_PATH \
    --change-address $USER_ADDR \
    --invalid-before $cur_slot \
    --required-signer $WALLET_PATH/$USER.skey \
    --out-file $TX_PATH/$FILE_NAME.raw

echo "Transaction built: $TX_PATH/$FILE_NAME.raw"

# Sign transaction
cardano-cli conway transaction sign \
    ${TESTNET_MAGIC} \
    --tx-body-file $TX_PATH/$FILE_NAME.raw \
    --out-file $TX_PATH/$FILE_NAME.sign \
    --signing-key-file $WALLET_PATH/$USER.skey

echo "Transaction signed: $TX_PATH/$FILE_NAME.sign"

# Submit transaction
echo ""
echo "Submitting transaction..."
cardano-cli conway transaction submit ${TESTNET_MAGIC} --tx-file $TX_PATH/$FILE_NAME.sign

echo ""
echo "=== VPN Access Token Minted Successfully ==="
echo "Token: $VPN_CS.$TN"
echo "Expiration: $(date -d @$((EX_UTC / 1000)) -u)"
