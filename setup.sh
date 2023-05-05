#!/bin/sh

# Depends on tshark
sudo apt-get update
sudo apt-get install -y tshark

# Pip3 requirements
pip3 install -r requirements.txt

# And requires the libiec61850 library
git clone https://github.com/mz-automation/libiec61850.git ./libiec61850
make -C trafficGen all

echo Setup complete!