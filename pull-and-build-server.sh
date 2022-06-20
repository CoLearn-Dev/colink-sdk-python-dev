#!/bin/bash
set -e
rm -rf colink-server
git clone --recursive git@github.com:CoLearn-Dev/colink-server-dev.git colink-server
cd colink-server
cargo build --all-targets
cd ..
