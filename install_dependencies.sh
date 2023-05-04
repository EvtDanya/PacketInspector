#!/bin/bash
# 1: chmod +x install_dependencies.sh
# 2:./install_dependencies.sh

# Install required packages
sudo apt-get update
sudo apt-get install python3 python3-pip python3-dev libpcap-dev -y

# Install Python packages
sudo pip3 install -r requirements.txt
echo "Dependencies installed successfully!"