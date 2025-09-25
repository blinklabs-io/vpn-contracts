#!/bin/bash

USER=$1

source env.sh
FILE_NAME="extend-vpn-access"

USER_ADDR=$(cat $WALLET_PATH/$USER.addr)
UTXO_IN_ADA=$(get_address_biggest_lovelace $USER_ADDR)
UTXO_VPN_IN="228ed68197413739cc62992874ff970df584e411a06343d2dc10e6be2fadff4a#0"
echo "UTXO_IN_ADA: $UTXO_IN_ADA"
VPN_ADDR=$(cat $VALIDATOR_PATH/vpn.addr)
NFT_CS=$(cardano-cli hash script --script-file $VALIDATOR_PATH/nft.plutus)
echo "NFT_CS: $NFT_CS"
UTXO_VPN_REF_DATA=$(get_UTxO_by_token $VPN_ADDR $NFT_CS.70726f7669646572)
echo "UTXO_VPN_REF_DATA: $UTXO_VPN_REF_DATA"
VPN_FILE="$VALIDATOR_PATH/vpn.plutus"
VPN_CS=$(cardano-cli hash script --script-file $VALIDATOR_PATH/vpn.plutus)
echo "VPN_CS: $VPN_CS"
TN=45E9EF1D20CC8D0EC33F0F8E32E3C7EF56BE71121A8F85B484864642FE79F23A #$(blake2b_hash $UTXO_IN_ADA)
echo "TN: $TN"
USER_PKH=$(cardano-cli address key-hash --payment-verification-key-file $WALLET_PATH/$USER.vkey)
#cur_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
cur_time=$(date -u --date="now - 1000 seconds" +"%Y-%m-%dT%H:%M:%SZ")
cur_slot=$(cardano-cli query slot-number "$cur_time"  $TESTNET_MAGIC)
#EX_UTC=$(( 1750786130200 + 259200 ))
#echo "cur_time: $EX_UTC"
CUR_UTC=$(( $(date -u --date="$cur_time" +%s%3N) ))
echo "CUR_UTC: $CUR_UTC"
echo "old: 1764579853000"
echo "to add: 259200000"
NEW_EX_TIME=$(( 1764579853000 + 259200000 ))
echo "NEW_EX_TIME: $NEW_EX_TIME"
vpn_datum=$(generate_vpn_data_json $USER_PKH 757320656173742d32 $NEW_EX_TIME)
DATUM_PATH=$DATUMS_PATH/"$USER"_vpn_data.json
REDEEMER_PATH=$REDEEMERS_PATH/user1_extend.json
echo $vpn_datum > $DATUM_PATH
cat $DATUM_PATH
redeemer=$(generate_vpn_extend_redeemer_json $USER_PKH $TN 0)
echo $redeemer > $REDEEMER_PATH

cardano-cli conway transaction build \
     ${TESTNET_MAGIC} \
    --tx-in-collateral ${UTXO_IN_ADA} \
    --tx-in ${UTXO_IN_ADA} \
    --read-only-tx-in-reference $UTXO_VPN_REF_DATA \
    --tx-in $UTXO_VPN_IN \
    --spending-tx-in-reference $VPN_TX_REF \
    --spending-plutus-script-v3 \
    --spending-reference-tx-in-inline-datum-present \
    --spending-reference-tx-in-redeemer-file $REDEEMER_PATH \
    --tx-out $VPN_ADDR+2000000+"1 $VPN_CS.$TN" \
    --tx-out-inline-datum-file $DATUM_PATH \
    --tx-out $(cat $WALLET_PATH/provider.addr)+5000000 \
    --change-address $USER_ADDR \
    --invalid-before $cur_slot \
    --required-signer $WALLET_PATH/$USER.skey \
    --out-file $TX_PATH/$FILE_NAME.raw
exit
cardano-cli conway transaction sign \
     ${TESTNET_MAGIC} \
    --tx-body-file $TX_PATH/$FILE_NAME.raw \
    --out-file $TX_PATH/$FILE_NAME.sign \
    --signing-key-file $WALLET_PATH/$USER.skey

cardano-cli conway transaction submit  ${TESTNET_MAGIC} --tx-file $TX_PATH/$FILE_NAME.sign