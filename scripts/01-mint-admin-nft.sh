#!/bin/bash

USER=$1

source env.sh
FILE_NAME="nft"

USER_ADDR=$(cat $WALLET_PATH/$USER.addr)
UTXO_IN_ADA=$(get_address_biggest_lovelace $USER_ADDR)
echo "UTXO_IN_ADA: $UTXO_IN_ADA"
NFT_FILE="$VALIDATOR_PATH/nft.plutus"
VPN_FILE="$VALIDATOR_PATH/vpn.plutus"
VPN_ADDR=$(cat $VALIDATOR_PATH/vpn.addr)
NFT_CS=$(cardano-cli hash script --script-file $NFT_FILE)
echo "NFT_CS: $NFT_CS"

cardano-cli conway transaction build \
    ${TESTNET_MAGIC} \
    --tx-in-collateral ${UTXO_IN_ADA} \
    --tx-in ${UTXO_IN_ADA} \
    --mint "1 $NFT_CS.70726f7669646572" \
    --mint-script-file $VALIDATOR_PATH/nft.plutus \
    --mint-redeemer-value '"provider"' \
    --change-address $USER_ADDR \
    --tx-out $VPN_ADDR+2000000+"1 $NFT_CS.70726f7669646572" \
    --tx-out-inline-datum-file $DATUMS_PATH/vpn_reference_data.json \
    --tx-out $USER_ADDR+16347830 \
    --tx-out-reference-script-file $VPN_FILE \
    --out-file $TX_PATH/$FILE_NAME.raw

cardano-cli conway transaction sign \
    ${TESTNET_MAGIC} \
    --tx-body-file $TX_PATH/$FILE_NAME.raw \
    --out-file $TX_PATH/$FILE_NAME.sign \
    --signing-key-file $WALLET_PATH/$USER.skey

cardano-cli conway transaction submit ${TESTNET_MAGIC} --tx-file $TX_PATH/$FILE_NAME.sign