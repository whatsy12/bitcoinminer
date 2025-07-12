# CLAUDE AI HAS MADE THIS WHOLE PROJECT
# How to use the miner, and how it works.
Real Network Features:

Bitcoin Core Integration: Connects to your Bitcoin Core node via RPC
Live Block Templates: Gets real block templates from the network
Merkle Root Calculation: Builds proper merkle trees from transactions
Block Submission: Submits found blocks to the Bitcoin network
Auto-Updates: Refreshes block templates every 30 seconds

How It Works:

Connection: Connects to your Bitcoin Core node (localhost:8332 by default)
Template Retrieval: Gets current block template with transactions
Mining: Performs double SHA-256 hashing with proper Bitcoin protocol
Submission: Submits valid blocks to the network for verification

Setup Requirements:
bash# Install dependencies
sudo apt-get install libcurl4-openssl-dev libjsoncpp-dev

# Compile
g++ -O3 -o network_miner network_miner.cpp -lcurl -ljsoncpp -lpthread -std=c++11
Bitcoin Core Setup:
You need a running Bitcoin Core node with RPC enabled. Add to bitcoin.conf:
server=1
rpcuser=your_username
rpcpassword=your_password
rpcallowip=127.0.0.1
Important Notes:

Real Mining: This connects to the actual Bitcoin network and can mine real blocks
Hardware Requirements: Modern Bitcoin mining requires ASIC hardware for profitability
Network Difficulty: Bitcoin's current difficulty makes CPU mining extremely unlikely to find blocks
Testnet Option: Consider using testnet for testing (-testnet flag in Bitcoin Core)

What Happens When You Find a Block:

The miner detects a valid hash
Constructs the complete block with all transactions
Submits to Bitcoin network via submitblock RPC
If accepted, you've mined a real Bitcoin block worth ~6.25 BTC + fees!
