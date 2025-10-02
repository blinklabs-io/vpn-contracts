#!/bin/bash

USER=$1

source env.sh
FILE_NAME="vpn-access"

selection=0
price=5000000
duration=259200000
region=757320656173742d31

USER_ADDR=$(cat $WALLET_PATH/$USER.addr)
UTXO_IN_ADA=$(get_address_biggest_lovelace $USER_ADDR)
echo "UTXO_IN_ADA: $UTXO_IN_ADA"
VPN_ADDR=$(cat $VALIDATOR_PATH/vpn.addr)
UTXO_VPN_REF_DATA=$(get_UTxO_by_token $VPN_ADDR $(cardano-cli hash script --script-file $VALIDATOR_PATH/nft.plutus).70726f7669646572)
echo "UTXO_VPN_REF_DATA: $UTXO_VPN_REF_DATA"
VPN_CS=$(cardano-cli hash script --script-file $VALIDATOR_PATH/vpn.plutus)
echo "VPN_CS: $VPN_CS"
TN=$(blake2b_hash $UTXO_IN_ADA)
echo "TN: $TN"
USER_PKH=$(cardano-cli address key-hash --payment-verification-key-file $WALLET_PATH/$USER.vkey)
cur_time=$(date -u --date="now - 400 seconds" +"%Y-%m-%dT%H:%M:%SZ")
echo "cur_time: $cur_time"
cur_slot=$(cardano-cli query slot-number "$cur_time" ${TESTNET_MAGIC})
EX_UTC=$(( $(date -u --date="$cur_time" +%s%3N) + $duration ))
echo "EX_UTC: $EX_UTC"
vpn_datum=$(generate_vpn_data_json $USER_PKH $region $EX_UTC)
DATUM_PATH=$DATUMS_PATH/"$USER"_vpn_data.json
echo $vpn_datum > $DATUM_PATH
cat $DATUM_PATH
redeemer=$(generate_vpn_access_redeemer_json $USER_PKH $region $selection $UTXO_IN_ADA)
echo $redeemer > $REDEEMERS_PATH/"$USER"_mint.json

cardano-cli conway transaction build \
    ${TESTNET_MAGIC} \
    --tx-in-collateral ${UTXO_IN_ADA} \
    --tx-in ${UTXO_IN_ADA} \
    --read-only-tx-in-reference $UTXO_VPN_REF_DATA \
    --mint "1 $VPN_CS.$TN" \
    --mint-tx-in-reference $VPN_TX_REF \
    --mint-plutus-script-v3 \
    --mint-reference-tx-in-redeemer-file $REDEEMERS_PATH/"$USER"_mint.json \
    --policy-id $VPN_CS \
    --tx-out $VPN_ADDR+2000000+"1 $VPN_CS.$TN" \
    --tx-out-inline-datum-file $DATUM_PATH \
    --tx-out $(cat $WALLET_PATH/provider.addr)+$price \
    --change-address $USER_ADDR \
    --invalid-before $cur_slot \
    --required-signer $WALLET_PATH/$USER.skey \
    --out-file $TX_PATH/$FILE_NAME.raw

cardano-cli conway transaction sign \
    ${TESTNET_MAGIC} \
    --tx-body-file $TX_PATH/$FILE_NAME.raw \
    --out-file $TX_PATH/$FILE_NAME.sign \
    --signing-key-file $WALLET_PATH/$USER.skey

cardano-cli conway transaction submit ${TESTNET_MAGIC} --tx-file $TX_PATH/$FILE_NAME.sign