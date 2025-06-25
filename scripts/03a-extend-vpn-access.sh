#!/bin/bash

USER=$1

source env.sh
FILE_NAME="extend-vpn-access"

USER_ADDR=$(cat $WALLET_PATH/$USER.addr)
UTXO_IN_ADA=$(get_address_biggest_lovelace $USER_ADDR)
UTXO_VPN_IN="0854e6e6adf135a30fe5531d161c2e698a65382f789c5232eee24626e82c3099#0"
echo "UTXO_IN_ADA: $UTXO_IN_ADA"
VPN_ADDR=$(cat $VALIDATOR_PATH/vpn.addr)
NFT_CS=$(cardano-cli hash script --script-file $VALIDATOR_PATH/nft.plutus)
echo "NFT_CS: $NFT_CS"
UTXO_VPN_REF_DATA=$(get_UTxO_by_token $VPN_ADDR $NFT_CS.61646d696e)
echo "UTXO_VPN_REF_DATA: $UTXO_VPN_REF_DATA"
VPN_FILE="$VALIDATOR_PATH/vpn.plutus"
VPN_CS=$(cardano-cli hash script --script-file $VALIDATOR_PATH/vpn.plutus)
echo "VPN_CS: $VPN_CS"
TN=6ecba140e0fc46aea2ad454fca1eda444f85c2d68c736f6db0c4d353d2b545a0 #$(blake2b_hash $UTXO_IN_ADA)
echo "TN: $TN"
USER_PKH=$(cardano-cli address key-hash --payment-verification-key-file $WALLET_PATH/$USER.vkey)
#cur_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
cur_time=$(date -u --date="now - 1000 seconds" +"%Y-%m-%dT%H:%M:%SZ")
cur_slot=$(cardano-cli query slot-number "$cur_time" --testnet-magic $TESTNET_MAGIC)
#EX_UTC=$(( 1750786130200 + 259200 ))
#echo "cur_time: $EX_UTC"
EX_UTC=$(( $(date -u --date="$cur_time" +%s%3N) + 259200 ))
vpn_datum=$(generate_vpn_data_json $USER_PKH 757320656173742d31 $EX_UTC)
DATUM_PATH=$DATUMS_PATH/"$USER"_vpn_data.json
REDEEMER_PATH=$REDEEMERS_PATH/user1_extend.json
echo $vpn_datum > $DATUM_PATH
cat $DATUM_PATH
redeemer=$(generate_vpn_extend_redeemer_json $USER_PKH $TN 0)
echo $redeemer > $REDEEMER_PATH

cardano-cli conway transaction build \
    --testnet-magic ${TESTNET_MAGIC} \
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

cardano-cli conway transaction sign \
    --testnet-magic ${TESTNET_MAGIC} \
    --tx-body-file $TX_PATH/$FILE_NAME.raw \
    --out-file $TX_PATH/$FILE_NAME.sign \
    --signing-key-file $WALLET_PATH/$USER.skey

cardano-cli conway transaction submit --testnet-magic ${TESTNET_MAGIC} --tx-file $TX_PATH/$FILE_NAME.sign