#!/bin/bash
#
# Extend VPN Access Token with Midnight ZK Proof
#
# This script extends an existing VPN access token using a ZK proof from
# Midnight instead of a direct ADA payment. The proof must be obtained
# from a Midnight payment transaction first.
#
# Usage: ./08-extend-vpn-midnight.sh <user> <vpn_utxo> <proof_file> [new_owner]
#
# Arguments:
#   user       - User wallet name (must have keys in wallets/)
#   vpn_utxo   - The UTxO containing the VPN token to extend (format: txhash#index)
#   proof_file - Path to JSON file containing Midnight proof data
#   new_owner  - (Optional) New owner's payment key hash for transfer
#
# Proof file format:
# {
#   "zk_proof": "<hex-encoded proof bytes>",
#   "nullifier": "<hex-encoded nullifier>",
#   "state_root": "<hex-encoded midnight state root>",
#   "selection": <pricing tier index>
# }
#

set -e

if [ $# -lt 3 ]; then
    echo "Usage: $0 <user> <vpn_utxo> <proof_file> [new_owner]"
    echo ""
    echo "Arguments:"
    echo "  user       - User wallet name"
    echo "  vpn_utxo   - UTxO containing VPN token (txhash#index)"
    echo "  proof_file - Path to Midnight proof JSON file"
    echo "  new_owner  - (Optional) New owner PKH for transfer"
    exit 1
fi

USER=$1
UTXO_VPN_IN=$2
PROOF_FILE=$3
NEW_OWNER=${4:-""}

source env.sh
FILE_NAME="extend-vpn-access-midnight"

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

echo "=== Extending VPN Access with Midnight Proof ==="
echo "User: $USER"
echo "VPN UTxO: $UTXO_VPN_IN"
echo "Selection: $SELECTION"
echo "Nullifier: ${NULLIFIER:0:16}..."
if [ -n "$NEW_OWNER" ]; then
    echo "New Owner: $NEW_OWNER"
fi

# Get pricing info (for duration calculation)
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

# Get nullifier policy ID
NULLIFIER_CS=$(derive_nullifier_policy $VPN_CS)
echo "NULLIFIER_CS: $NULLIFIER_CS"

# Query current VPN token datum to get region and current expiration
echo ""
echo "Querying current VPN token..."
cardano-cli query utxo ${TESTNET_MAGIC} --tx-in $UTXO_VPN_IN --out-file /tmp/vpn_utxo.json
VPN_TOKEN=$(cat /tmp/vpn_utxo.json | jq -r 'to_entries[0].value.value | to_entries[] | select(.key != "lovelace") | .key + "." + (.value | to_entries[0].key)')
TN=$(echo $VPN_TOKEN | cut -d'.' -f2)
echo "VPN Token: $VPN_TOKEN"

# Get current datum (would need to query the UTxO for this)
# For now, we'll need the user to provide region or query it
# This is a simplification - in production, query the datum
CURRENT_DATUM=$(cat /tmp/vpn_utxo.json | jq -r 'to_entries[0].value.inlineDatum')
CURRENT_REGION=$(echo $CURRENT_DATUM | jq -r '.fields[1].bytes')
CURRENT_EX_TIME=$(echo $CURRENT_DATUM | jq -r '.fields[2].int')
CURRENT_OWNER=$(echo $CURRENT_DATUM | jq -r '.fields[0].bytes')
echo "Current Region: $CURRENT_REGION"
echo "Current Expiration: $CURRENT_EX_TIME"

# Determine new owner
if [ -n "$NEW_OWNER" ]; then
    OWNER_PKH=$NEW_OWNER
else
    OWNER_PKH=$CURRENT_OWNER
fi

# Calculate new expiration time
cur_time=$(date -u --date="now - 1000 seconds" +"%Y-%m-%dT%H:%M:%SZ")
cur_slot=$(cardano-cli query slot-number "$cur_time" ${TESTNET_MAGIC})
CUR_UTC=$(( $(date -u --date="$cur_time" +%s%3N) ))
echo "CUR_UTC: $CUR_UTC"

# If not expired, add to current; otherwise add to now
if [ $CUR_UTC -lt $CURRENT_EX_TIME ]; then
    NEW_EX_TIME=$(( $CURRENT_EX_TIME + $duration ))
else
    NEW_EX_TIME=$(( $CUR_UTC + $duration ))
fi
echo "NEW_EX_TIME: $NEW_EX_TIME"

# Generate VPN datum with new expiration
vpn_datum=$(generate_vpn_data_json $OWNER_PKH $CURRENT_REGION $NEW_EX_TIME)
DATUM_PATH=$DATUMS_PATH/"$USER"_vpn_extend_midnight.json
echo $vpn_datum > $DATUM_PATH
echo "VPN Datum:"
cat $DATUM_PATH

# Generate redeemer with proof
redeemer=$(generate_vpn_extend_with_proof_redeemer_json \
    "$NEW_OWNER" \
    $SELECTION \
    $ZK_PROOF \
    $NULLIFIER \
    $STATE_ROOT)
REDEEMER_PATH=$REDEEMERS_PATH/"$USER"_extend_midnight.json
echo $redeemer > $REDEEMER_PATH
echo "Redeemer saved to: $REDEEMER_PATH"

# Build transaction
echo ""
echo "Building transaction..."
cardano-cli conway transaction build \
    ${TESTNET_MAGIC} \
    --tx-in-collateral ${UTXO_IN_ADA} \
    --tx-in ${UTXO_IN_ADA} \
    --tx-in $UTXO_VPN_IN \
    --spending-tx-in-reference $VPN_TX_REF \
    --spending-plutus-script-v3 \
    --spending-reference-tx-in-inline-datum-present \
    --spending-reference-tx-in-redeemer-file $REDEEMER_PATH \
    --read-only-tx-in-reference $UTXO_VPN_REF_DATA \
    --read-only-tx-in-reference $UTXO_MIDNIGHT_CONFIG \
    --mint "1 $NULLIFIER_CS.$NULLIFIER" \
    --mint-tx-in-reference $VPN_TX_REF \
    --mint-plutus-script-v3 \
    --mint-reference-tx-in-redeemer-file $REDEEMER_PATH \
    --policy-id $NULLIFIER_CS \
    --tx-out $VPN_ADDR+2000000+"1 $VPN_CS.$TN" \
    --tx-out-inline-datum-file $DATUM_PATH \
    --change-address $USER_ADDR \
    --invalid-before $cur_slot \
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
echo "=== VPN Access Extended Successfully ==="
echo "Token: $VPN_CS.$TN"
echo "New Expiration: $(date -d @$((NEW_EX_TIME / 1000)) -u)"

# Cleanup
rm -f /tmp/vpn_utxo.json
