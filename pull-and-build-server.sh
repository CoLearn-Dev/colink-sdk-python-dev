#!/bin/bash
set -e
rm -rf colink-server-dev
git clone --recursive git@github.com:CoLearn-Dev/colink-server-dev.git colink-server-dev
cd colink-server-dev
cargo build --all-targets
cd ..
rm -rf colink-protocol-remote-storage-dev
git clone --recursive git@github.com:CoLearn-Dev/colink-protocol-remote-storage-dev.git colink-protocol-remote-storage-dev
cd colink-protocol-remote-storage-dev
cargo build --all-targets
cd ..
