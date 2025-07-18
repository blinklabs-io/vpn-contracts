#!/bin/bash

USER=$1

source env.sh
FILE_NAME="burn-vpn-access"

USER_ADDR=$(cat $WALLET_PATH/$USER.addr)
UTXO_IN_ADA=$(get_address_biggest_lovelace $USER_ADDR)
UTXO_VPN_IN="e4cde36e6a111cdd11a6df6be13ea7aaad4ba28adddd5db3cf9a795d9c7fa6f5#0"
echo "UTXO_IN_ADA: $UTXO_IN_ADA"
VPN_ADDR=$(cat $VALIDATOR_PATH/vpn.addr)
NFT_CS=$(cardano-cli hash script --script-file $VALIDATOR_PATH/nft.plutus)
echo "NFT_CS: $NFT_CS"
VPN_CS=$(cardano-cli hash script --script-file $VALIDATOR_PATH/vpn.plutus)
echo "VPN_CS: $VPN_CS"
TN=b6fcb0d7aad21741846f2e3cb31b27c4935cc9e3d5bc3a87060db04dba40d46f #$(blake2b_hash $UTXO_IN_ADA)
echo "TN: $TN"
USER_PKH=$(cardano-cli address key-hash --payment-verification-key-file $WALLET_PATH/$USER.vkey)
cur_slot=$(cardano-cli query tip --testnet-magic $TESTNET_MAGIC | jq '.slot')
echo "cur_slot: $cur_slot"
REDEEMER_PATH=$REDEEMERS_PATH/"$USER"_burn.json
redeemer=$(generate_vpn_burn_redeemer_json $TN)
echo "redeemer: $redeemer"
echo $redeemer > $REDEEMER_PATH

cardano-cli conway transaction build \
    --testnet-magic ${TESTNET_MAGIC} \
    --tx-in-collateral ${UTXO_IN_ADA} \
    --tx-in ${UTXO_IN_ADA} \
    --tx-in $UTXO_VPN_IN \
    --spending-tx-in-reference $VPN_TX_REF \
    --spending-plutus-script-v3 \
    --spending-reference-tx-in-inline-datum-present \
    --spending-reference-tx-in-redeemer-file $REDEEMER_PATH \
    --mint "-1 $VPN_CS.$TN" \
    --mint-tx-in-reference $VPN_TX_REF \
    --mint-plutus-script-v3 \
    --mint-reference-tx-in-redeemer-file $REDEEMER_PATH \
    --policy-id $VPN_CS \
    --change-address $USER_ADDR \
    --invalid-before $cur_slot \
    --required-signer $WALLET_PATH/$USER.skey \
    --out-file $TX_PATH/$FILE_NAME.raw

cardano-cli conway transaction sign \
    --testnet-magic ${TESTNET_MAGIC} \
    --tx-body-file $TX_PATH/$FILE_NAME.raw \
    --out-file $TX_PATH/$FILE_NAME.sign \
    --signing-key-file $WALLET_PATH/$USER.skey

cardano-cli conway transaction submit --testnet-magic ${TESTNET_MAGIC} --tx-file $TX_PATH/$FILE_NAME.sign