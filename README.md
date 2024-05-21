# CJ-Coin
# Version 1.0

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)

## Introduction
CJ-Coin is a proof-of-work cryptocurrency written in Python, meant to resemble a simplified version of bitcoin, I created this out of curiosity of how cryptocurrencies work,
and as a learning experience in a variety of different topics including cryptography, SQL databases, Flask, APIs, networking, and the blockchain.
This project serves as a learning experience to other people as the code is extremely simple to follow, compared to the code of other cryptocurrencies.

## Features

- CJ-Coin includes a robust node discovery protocol, which simply gets a list of nodes from a set of trusted and hard coded 'seed nodes', it then broadcasts a discovery method to all other nodes the seed node send. Whenever new blocks and transactions are created, it is broadcasted to all other nodes in their 'peers' database.

- CJ-Coin includes a simple transaction verification system, checking if the transactions inputs are in the 'utxos' database and belong to their address, and add up to the amount in their outputs. Then, the node just checks if the signature of the transaction matches the public key sent.

- CJ-Coin includes a simple block verification system, verifying that the blocks merkle root matches the transactions, that the transactions all exist, the timestamp is equal or less than the nodes timestamp, and that the difficulty is correct.

- CJ-Coin nodes manage API calls and requests easily in a organised manner by making use of the Flask framework.

- CJ-Coins 'miner_client' file includes a bare bones terminal UI for sending transactions, and mining blocks.

- Access control for both nodes and clients is accomplished through encrypting the private keys through AES with a password,
and placing the password in a separate file which is hashed, salted, and peppered.

## Prerequisites
- Have to have python3 installed, atleast version `3.12.2`:
You can install python 3.12.2 by following: `https://www.python.org/downloads/`
- Must have pip installed, atleast version:
You can install pip by following: ``

## Installation
## There are two ways to install CJ-Coin:
- [The Basic Method](#basic)
- [The Virtual Environment Method](#virtualenv)

## The Basic Method
1. Clone the repository:
```sh
git clone https://github.com/CJ-programming/CJ-Coin
cd CJ-Coin
```
2. Install dependencies
```sh
pip install -r requirements.txt
```

## The Virtual Environment Method
1. Install virtualenv
```sh
pip install virtualenv
```

## Usage
### The network consists of two types of nodes:
1. A seed node:
The seed nodes are the first nodes that should be ran, and can be ran straight away, without being bootstrapped, the IP addresses of the seed nodes are hard coded and other nodes
connect to the every other node by first accessing the seed node.

2. A node:
The node is tasked with validating transactions and blocks, and broadcasting and transferring them across.

### To run a seed node you type the command:
```sh
cd src/seed_node # change directory to seed node
python api.py -r # run api.py -r script
```

### To run a node you must bootstrapped the node, making it visible to other nodes, and then run it. You can do this by typing the command:
```sh
cd src/node
python api.py -br # the -r flag is for running, and the -b flag is for boostrapping
```


1. To set up the network, the first thing you need to do is run the seed node, you can do this by typing:
```sh
cd src/seed_node/
python api.py -r

The flags of the seed node
```