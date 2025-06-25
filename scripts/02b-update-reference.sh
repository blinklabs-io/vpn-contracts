#!/bin/bash

USER=$1

source env.sh
FILE_NAME="update-reference"

USER_ADDR=$(cat $WALLET_PATH/$USER.addr)
UTXO_IN_ADA=$(get_address_biggest_lovelace $USER_ADDR)
echo "UTXO_IN_ADA: $UTXO_IN_ADA"
VPN_ADDR=$(cat $VALIDATOR_PATH/vpn.addr)
NFT_CS=$(cardano-cli hash script --script-file $VALIDATOR_PATH/nft.plutus)
echo "NFT_CS: $NFT_CS"
UTXO_VPN_REF_DATA=$(get_UTxO_by_token $VPN_ADDR $NFT_CS.61646d696e)
echo "UTXO_VPN_REF_DATA: $UTXO_VPN_REF_DATA"
DATUM_PATH=$DATUMS_PATH/vpn_reference_data.json
REDEEMER_PATH=$REDEEMERS_PATH/update_ref_data.json
redeemer=$(generate_vpn_update_ref_data_redeemer_json "$(cat $DATUM_PATH)")
echo $redeemer > $REDEEMER_PATH

cardano-cli conway transaction build \
    --testnet-magic ${TESTNET_MAGIC} \
    --tx-in-collateral ${UTXO_IN_ADA} \
    --tx-in ${UTXO_IN_ADA} \
    --tx-in $UTXO_VPN_REF_DATA \
    --spending-tx-in-reference $VPN_TX_REF \
    --spending-plutus-script-v3 \
    --spending-reference-tx-in-inline-datum-present \
    --spending-reference-tx-in-redeemer-file $REDEEMER_PATH \
    --change-address $USER_ADDR \
    --tx-out $VPN_ADDR+2000000+"1 $NFT_CS.61646d696e" \
    --tx-out-inline-datum-file $DATUM_PATH \
    --required-signer $WALLET_PATH/$USER.skey \
    --out-file $TX_PATH/$FILE_NAME.raw

cardano-cli conway transaction sign \
    --testnet-magic ${TESTNET_MAGIC} \
    --tx-body-file $TX_PATH/$FILE_NAME.raw \
    --out-file $TX_PATH/$FILE_NAME.sign \
    --signing-key-file $WALLET_PATH/$USER.skey

cardano-cli conway transaction submit --testnet-magic ${TESTNET_MAGIC} --tx-file $TX_PATH/$FILE_NAME.sign