# run manually once you set env variables
# PRIVATE_KEY, RPC_URL TENDERLY_ACCESS_TOKEN, TENDERLY_VERIFIER_URL
RPC_URL=https://virtual.mainnet.rpc.tenderly.co/c5ed9a3b-7ad5-4d6a-8e4b-76a4b00ba6ea
TENDERLY_VERIFIER_URL=$RPC_URL/verify/etherscan
PRIVATE_KEY=0x...
TENDERLY_ACCESS_TOKEN=...

forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY src/IntentECDSAValidator.sol:ECDSAValidator --etherscan-api-key $TENDERLY_ACCESS_TOKEN --verify --verifier-url $TENDERLY_VERIFIER_URL