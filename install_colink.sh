#!/bin/bash
set -e
#
# Tested on Ubuntu 20.04/22.04
#
if ! [ -f "./host_token.txt" ]; then
    sudo apt update && sudo apt install git g++ cmake pkg-config libssl-dev protobuf-compiler -y
fi
if ! [ -x "$(command -v cargo)" ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi
if ! dpkg -s rabbitmq-server >/dev/null 2>&1; then
    sudo apt install rabbitmq-server -y
    sudo rabbitmq-plugins enable rabbitmq_management
    sudo bash -c "cat > /etc/rabbitmq/rabbitmq.conf <<- EOF
listeners.tcp.default = 5672
# listeners.ssl.default = 5671
# ssl_options.cacertfile = <path to cert>/ca.pem
# ssl_options.certfile = <path to cert>/server.pem
# ssl_options.keyfile = <path to cert>/server-key.pem
management.tcp.port       = 15672
management.tcp.idle_timeout       = 120000
management.tcp.inactivity_timeout = 120000
management.tcp.request_timeout    = 10000
# management.ssl.port       = 15671
# management.ssl.cacertfile = <path to cert>/ca.pem
# management.ssl.certfile   = <path to cert>/server.pem
# management.ssl.keyfile    = <path to cert>/server-key.pem
# management.ssl.idle_timeout       = 120000
# management.ssl.inactivity_timeout = 120000
# management.ssl.request_timeout    = 10000
EOF"
    sudo systemctl restart rabbitmq-server.service
fi
if ! [ -d "./colink-server-dev" ]; then
    export GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no"
    git clone --recursive git@github.com:CoLearn-Dev/colink-server-dev.git
fi
cd colink-server-dev
cargo build
nohup cargo run -- --address "127.0.0.1" --port 12300 --mq-amqp amqp://guest:guest@localhost:5672 --mq-api http://guest:guest@localhost:15672/api >/dev/null 2>&1 &
sleep 2 # TODO check if the server has started
host_token=`cat host_token.txt`
echo "host_token: ${host_token}"
cp host_token.txt ../
cd ..
if ! [ -d "./colink-sdk-a-rust-dev" ]; then
    export GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no"
    git clone --recursive git@github.com:CoLearn-Dev/colink-sdk-a-rust-dev.git
fi
cd colink-sdk-a-rust-dev
cargo build --all-targets
read -p "number of test users [2]:" user_num
user_num=${user_num:-2}
cargo run --example host_import_users_and_exchange_guest_jwts http://127.0.0.1:12300 $host_token $user_num > user_token.txt
cat user_token.txt
cp user_token.txt ../
cd ..
