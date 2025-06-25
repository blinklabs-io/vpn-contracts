#!/bin/bash
# get balance of a wallet

USER=$1 # wallet name stored in ../preprod/wallets/

source env.sh

cardano-cli query utxo --testnet-magic ${TESTNET_MAGIC} --address $(cat $WALLET_PATH/$USER.addr)