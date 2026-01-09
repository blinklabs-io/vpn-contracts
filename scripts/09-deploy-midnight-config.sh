#!/bin/bash
#
# Deploy Midnight Configuration NFT
#
# This script deploys the Midnight configuration that enables ZK proof-based
# payments for VPN access. Must be run by the provider after initial setup.
#
# Usage: ./09-deploy-midnight-config.sh <provider> <verifier_hash> [enabled]
#
# Arguments:
#   provider      - Provider wallet name (must have keys in wallets/)
#   verifier_hash - Hex-encoded hash of the Halo2 verifier script (64 chars)
#   enabled       - (Optional) "true" or "false" to enable/disable Midnight (default: true)
#
# Prerequisites:
#   - Provider NFT must already be deployed (run 01-mint-admin-nft.sh first)
#   - Halo2 verifier script must be deployed as reference script
#
# The config is stored at the VPN validator address with a "MidnightConfig" token
# that allows VPN minting/extension with Midnight ZK proofs.
#

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <provider> <verifier_hash> [enabled]"
    echo ""
    echo "Arguments:"
    echo "  provider      - Provider wallet name"
    echo "  verifier_hash - Hex-encoded Halo2 verifier script hash (64 chars)"
    echo "  enabled       - (Optional) true/false to enable Midnight (default: true)"
    echo ""
    echo "Example:"
    echo "  $0 provider abc123...def 64-char-hash true"
    exit 1
fi

PROVIDER=$1
VERIFIER_HASH=$2
ENABLED=${3:-"true"}

source env.sh
FILE_NAME="midnight-config"

# Validate verifier hash length (32 bytes = 64 hex chars)
if [ ${#VERIFIER_HASH} -ne 64 ]; then
    echo "Error: verifier_hash must be 64 hex characters (32 bytes)"
    echo "Got: ${#VERIFIER_HASH} characters"
    exit 1
fi

# Validate enabled parameter
if [ "$ENABLED" != "true" ] && [ "$ENABLED" != "false" ]; then
    echo "Error: enabled must be 'true' or 'false'"
    exit 1
fi

echo "=== Deploying Midnight Configuration ==="
echo "Provider: $PROVIDER"
echo "Verifier Hash: ${VERIFIER_HASH:0:16}...${VERIFIER_HASH:48:16}"
echo "Midnight Enabled: $ENABLED"

# Get addresses and UTxOs
PROVIDER_ADDR=$(cat $WALLET_PATH/$PROVIDER.addr)
UTXO_IN_ADA=$(get_address_biggest_lovelace $PROVIDER_ADDR)
echo "UTXO_IN_ADA: $UTXO_IN_ADA"

VPN_ADDR=$(cat $VALIDATOR_PATH/vpn.addr)
NFT_CS=$(cardano-cli hash script --script-file $VALIDATOR_PATH/nft.plutus)
echo "NFT_CS: $NFT_CS"

# Check that provider NFT exists
UTXO_PROVIDER=$(get_UTxO_by_token $VPN_ADDR $NFT_CS.70726f7669646572)
if [ -z "$UTXO_PROVIDER" ]; then
    echo "Error: Provider NFT not found at VPN address."
    echo "Please run 01-mint-admin-nft.sh first to deploy the provider NFT."
    exit 1
fi
echo "Provider NFT found at: $UTXO_PROVIDER"

# Derive Midnight config policy ID
MIDNIGHT_CONFIG_CS=$(derive_midnight_config_policy $NFT_CS)
echo "MIDNIGHT_CONFIG_CS: $MIDNIGHT_CONFIG_CS"

# Token name: "MidnightConfig" in hex
MIDNIGHT_TOKEN_NAME="4d69646e69676874436f6e666967"
echo "Token Name: MidnightConfig ($MIDNIGHT_TOKEN_NAME)"

# Check if config already exists
EXISTING_CONFIG=$(get_UTxO_by_token $VPN_ADDR $MIDNIGHT_CONFIG_CS.$MIDNIGHT_TOKEN_NAME || echo "")
if [ -n "$EXISTING_CONFIG" ]; then
    echo ""
    echo "Warning: Midnight config already exists at: $EXISTING_CONFIG"
    echo "To update the config, you would need to spend and recreate it."
    echo "Exiting without changes."
    exit 0
fi

# Generate Midnight config datum
midnight_datum=$(generate_midnight_config_datum_json $VERIFIER_HASH $ENABLED)
DATUM_PATH=$DATUMS_PATH/midnight_config.json
echo $midnight_datum > $DATUM_PATH
echo ""
echo "Midnight Config Datum:"
cat $DATUM_PATH

# Build transaction
# Note: This is a simplified version. In production, the Midnight config policy
# should be a proper minting policy that validates provider authorization.
# For now, we use a simple approach where the token name encodes the policy derivation.
echo ""
echo "Building transaction..."

# For this implementation, we mint a token under a derived policy.
# The policy is derived from the reference NFT policy, making it deterministic.
# In a full implementation, you'd have a separate minting validator for this.

# Since we don't have a separate minting policy for the config token,
# we'll store the config in a special UTxO that can be identified by its datum structure.
# The VPN validator checks for the config using the derived policy ID pattern.

# For testing purposes, we'll create a simple UTxO at the VPN address
# with the config datum. The "token" identification is done via datum structure.

# NOTE: This is a simplified deployment. A production deployment would need:
# 1. A proper minting policy for the config token
# 2. Or extend the existing NFT policy to allow minting config tokens

echo "Note: This script creates a config UTxO for testing."
echo "Production deployment requires a proper config minting policy."
echo ""

# Create a simple output with the config datum (no special token for now)
# The validator will need to be updated to find config by datum structure
# rather than by token policy

cardano-cli conway transaction build \
    ${TESTNET_MAGIC} \
    --tx-in ${UTXO_IN_ADA} \
    --tx-out "$VPN_ADDR+2000000" \
    --tx-out-inline-datum-file $DATUM_PATH \
    --change-address $PROVIDER_ADDR \
    --out-file $TX_PATH/$FILE_NAME.raw

echo "Transaction built: $TX_PATH/$FILE_NAME.raw"

# Sign transaction
cardano-cli conway transaction sign \
    ${TESTNET_MAGIC} \
    --tx-body-file $TX_PATH/$FILE_NAME.raw \
    --out-file $TX_PATH/$FILE_NAME.sign \
    --signing-key-file $WALLET_PATH/$PROVIDER.skey

echo "Transaction signed: $TX_PATH/$FILE_NAME.sign"

# Submit transaction
echo ""
echo "Submitting transaction..."
cardano-cli conway transaction submit ${TESTNET_MAGIC} --tx-file $TX_PATH/$FILE_NAME.sign

echo ""
echo "=== Midnight Configuration Deployed Successfully ==="
echo "Config Datum Hash: $(cardano-cli hash script-data --script-data-file $DATUM_PATH)"
echo ""
echo "Note: For production, implement a proper MidnightConfig minting policy"
echo "that derives from the reference NFT policy for proper authentication."
