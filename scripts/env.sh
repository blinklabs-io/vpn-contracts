export REPO_HOME="$HOME/blinklabs/vpn-contracts" #path to this repository
#export NETWORK_DIR_PATH="$REPO_HOME/preprod" # path to network in use (preprod)
#export TESTNET_MAGIC=$(echo "--testnet-magic 1")
#export VPN_TX_REF="ea7e4f0147eeba9a17c519e1652ed933262d30fe462bf418ece18dc27a2c13ba#1" # preprod
export NETWORK_DIR_PATH="$REPO_HOME/mainnet" # path to network in use (mainnet)
export TESTNET_MAGIC=$(echo "--mainnet")
export VPN_TX_REF="ea7e4f0147eeba9a17c519e1652ed933262d30fe462bf418ece18dc27a2c13ba#1" # mainnet
export TX_PATH="$NETWORK_DIR_PATH/tx"

export WALLET_PATH="$NETWORK_DIR_PATH/wallets"

export VALIDATOR_PATH="$NETWORK_DIR_PATH/validators"
export DATUMS_PATH="$NETWORK_DIR_PATH/datums"
export REDEEMERS_PATH="$NETWORK_DIR_PATH/redeemers"

##### Tx functions #####

#!/bin/bash

blake2b_256_txoutref() {
    local tx_ref="$1"
    local tx_hash="${tx_ref%#*}"
    local tx_idx="${tx_ref#*#}"
    
    python3 << EOF
import struct
import hashlib

tx_hash = "$tx_hash"
tx_idx = int("$tx_idx")

tx_hash_bytes = bytes.fromhex(tx_hash)

# Manually construct CBOR with indefinite array (serialise_data)
output = bytearray()
output.append(0xd8)  # Tag 121
output.append(0x79)
output.append(0x9f)  # Indefinite array start
output.append(0x58)  # Byte string
output.append(len(tx_hash_bytes))
output.extend(tx_hash_bytes)

# Integer index
if tx_idx <= 23:
    output.append(tx_idx)
elif tx_idx <= 255:
    output.append(0x18)
    output.append(tx_idx)
else:
    output.append(0x19)
    output.extend(struct.pack('>H', tx_idx))

output.append(0xff)  # Indefinite array end

# blake2b_256
hash_result = hashlib.blake2b(bytes(output), digest_size=32).digest()
print(hash_result.hex())
EOF
}

generate_vpn_data_json() {
  local str1="$1"
  local str2="$2"
  local int_val="$3"

  jq -n --arg b1 "$str1" --arg b2 "$str2" --argjson i "$int_val" '{
    constructor: 1,
    fields: [
      {bytes: $b1},
      {bytes: $b2},
      {int: $i}
    ]
  }'
}

generate_vpn_update_ref_data_redeemer_json() {
  local datum=$1
  local pricing=$(echo $datum | jq '.fields[0].list')
  local regions=$(echo $datum | jq '.fields[1].list')
  jq -n --argjson l1 "$pricing" --argjson l2 "$regions" '{
  constructor: 1, 
  fields: [
    {list: $l1
    },
    {list: $l2
    }
  ]
}'
}

generate_vpn_access_redeemer_json() {
  local pkh="$1"
  local region="$2"
  local selection="$3"
  local txin="$4"
  local tx_id=$(echo "$txin" | cut -d'#' -f1)
  local output_index=$(echo "$txin" | cut -d'#' -f2)

  jq -n --arg b1 "$pkh" --arg b2 "$region" --argjson i1 "$selection" --arg b3 "$tx_id" --argjson i2 "$output_index" '{
    constructor: 0,
    fields: [
      {bytes: $b1},
      {bytes: $b2},
      {int: $i1},
      {constructor: 0,
      fields: [
        {bytes: $b3},
        {int: $i2}
        ]
      }
    ]
  }'
}

generate_vpn_extend_redeemer_json() {
  local pkh="$1"
  local selection="$2"

  jq -n --arg b1 "$pkh" --argjson i1 "$selection" '{
    constructor: 2,
    fields: [
      {bytes: $b1},
      {int: $i1}
    ]
  }'
}

generate_vpn_burn_redeemer_json() {
  jq -n '{
    constructor: 3,
    fields: [
    ]
  }'
}

# $1 = address
get_address_biggest_lovelace(){
    cardano-cli query utxo ${TESTNET_MAGIC} --address $1 --out-file utxos.tmp
    max_utxo=$(cat utxos.tmp | jq 'with_entries(select((.value.value | length) == 1)) | to_entries | max_by(.value.value.lovelace)')
    rm utxos.tmp
    echo $(echo $max_utxo | jq -r '.key')
}

get_UTxO_by_token() {
    local ADDRESS="$1"
    local TOKEN="$2"

    local utxo_info
    utxo_info=$(cardano-cli query utxo --address "$ADDRESS" ${TESTNET_MAGIC} | tail -n +3)

    local utxo_entries
    IFS=$'\n' read -r -d '' -a utxo_entries <<<"$utxo_info"

    for entry in "${utxo_entries[@]}"; do
        entry_parts=($entry)
        utxo_hash=${entry_parts[0]}
        utxo_id=${entry_parts[1]}
        utxo_attached_token=${entry_parts[6]}

        if [[ $utxo_attached_token == "$TOKEN" ]]; then
            echo "$utxo_hash#$utxo_id"
            return 0
        fi
    done

    return 2
}
