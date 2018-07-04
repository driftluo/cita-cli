#!/usr/bin/env bash
rm ./src/protos/blockchain.rs
protoc --rust_out ./src/protos/ ./proto/blockchain.proto
