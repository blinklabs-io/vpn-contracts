export REPO_HOME="$HOME/blinklabs/vpn-contracts" #path to this repository
export NETWORK_DIR_PATH="$REPO_HOME/preprod" # path to network in use (preprod/private)
export TESTNET_MAGIC=1

export VPN_TX_REF="b32277b746cf0f8f9c84b9fcd1e07fdf53bbdddad25942ada26a086a2b178868#1"
export TX_PATH="$NETWORK_DIR_PATH/tx"
export EMPTY_TX="$TX_PATH/empty-tx.raw"

export WALLET_PATH="$NETWORK_DIR_PATH/wallets"
export WALLET_REF_SCR_NAME="wallet-ref-scr"

export VALIDATOR_PATH="$NETWORK_DIR_PATH/validators"
export DATUMS_PATH="$NETWORK_DIR_PATH/datums"
export REDEEMERS_PATH="$NETWORK_DIR_PATH/redeemers"

##### Tx functions #####

#!/bin/bash

blake2b_hash() {
    local input="$1"
    #local hex_part="$(to_upper ${input%#*})"
    local hex_part="${input%#*}"
    local index_part="${input#*#}"
    
    # Strip any whitespace and 0x prefixes
    hex_part=$(echo "$hex_part" | tr -d ' \t\n\r' | sed 's/^0[Xx]//')
    
    local le_index=""
    
    # Stop if input is zero
    if (( index_part == 0 )); then
        echo ""
        return
    fi

    # Extract bytes one by one (little-endian order)
    while (( index_part > 0 )); do
        byte=$(( index_part & 0xFF ))
        le_index+=$(printf "%02x" "$byte")
        index_part=$(( index_part >> 8 ))
    done

    # Combine
    local combined="${hex_part}${le_index}"
    
    # Validate hex string
    if [[ ! "$combined" =~ ^[0-9A-Fa-f]+$ ]]; then
        echo "ERROR: Invalid hex string: $combined" >&2
        return 1
    fi
    
    # Hash with Blake2b using Python
    python3 -c "
import hashlib
import binascii
data = binascii.unhexlify('$combined')
hash_obj = hashlib.blake2b(data, digest_size=32)
print(hash_obj.hexdigest().upper())
"
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
  local tn="$2"
  local selection="$3"

  jq -n --arg b1 "$pkh" --arg b2 "$tn" --argjson i1 "$selection" '{
    constructor: 2,
    fields: [
      {constructor: 1,
      fields: [
        ]
      },
      {bytes: $b2},
      {int: $i1}
    ]
  }'
}

# $1 = address
get_address_biggest_lovelace(){
    cardano-cli query utxo --testnet-magic ${TESTNET_MAGIC} --address $1 --out-file utxos.tmp
    max_utxo=$(cat utxos.tmp | jq 'with_entries(select((.value.value | length) == 1)) | to_entries | max_by(.value.value.lovelace)')
    rm utxos.tmp
    echo $(echo $max_utxo | jq -r '.key')
}

get_UTxO_by_token() {
    local ADDRESS="$1"
    local TOKEN="$2"

    local utxo_info
    utxo_info=$(cardano-cli query utxo --address "$ADDRESS" --testnet-magic ${TESTNET_MAGIC} | tail -n +3)

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