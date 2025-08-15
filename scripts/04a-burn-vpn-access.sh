#!/bin/bash

USER=$1

source env.sh
FILE_NAME="burn-vpn-access"

USER_ADDR=$(cat $WALLET_PATH/$USER.addr)
UTXO_IN_ADA=$(get_address_biggest_lovelace $USER_ADDR)
UTXO_VPN_IN="8a619902f2c54d0a7005c38511a567488b498e98c7cb1cf31276f3749b0d02a4#0"
echo "UTXO_IN_ADA: $UTXO_IN_ADA"
VPN_ADDR=$(cat $VALIDATOR_PATH/vpn.addr)
VPN_CS=$(cardano-cli hash script --script-file $VALIDATOR_PATH/vpn.plutus)
echo "VPN_CS: $VPN_CS"
TN=86f83cb55933d0aaced147988d9c1c7b5ed390ff6a99b842864f1f79bcbde6f4 #$(blake2b_hash $UTXO_IN_ADA)
echo "TN: $TN"
USER_PKH=$(cardano-cli address key-hash --payment-verification-key-file $WALLET_PATH/$USER.vkey)
cur_slot=$(cardano-cli query tip  $TESTNET_MAGIC | jq '.slot')
echo "cur_slot: $cur_slot"
REDEEMER_PATH=$REDEEMERS_PATH/"$USER"_burn.json
redeemer=$(generate_vpn_burn_redeemer_json $TN)
echo "redeemer: $redeemer"
echo $redeemer > $REDEEMER_PATH

cardano-cli conway transaction build \
     ${TESTNET_MAGIC} \
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
     ${TESTNET_MAGIC} \
    --tx-body-file $TX_PATH/$FILE_NAME.raw \
    --out-file $TX_PATH/$FILE_NAME.sign \
    --signing-key-file $WALLET_PATH/$USER.skey

cardano-cli conway transaction submit  ${TESTNET_MAGIC} --tx-file $TX_PATH/$FILE_NAME.sign