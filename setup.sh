#!/bin/sh

# Depends on tcpdump
sudo apt-get update
sudo apt-get install -y tcpdump

# Pip3 requirements
pip3 install -r requirements.txt

# And requires the libiec61850 library
git clone https://github.com/mz-automation/libiec61850.git ./libiec61850
make -C trafficGen all

echo Setup complete!
