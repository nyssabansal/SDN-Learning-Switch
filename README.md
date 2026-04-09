# SDN Learning Switch using POX Controller

## Problem Statement
Implement an SDN controller that mimics a learning switch by dynamically learning MAC addresses and installing forwarding rules.

## Tools Used
- Mininet
- POX Controller
- OpenFlow

## Setup Steps

1. Clone POX:
git clone https://github.com/noxrepo/pox
cd pox

2. Run Controller:
./pox.py my_controller

3. Run Mininet:
sudo mn --topo single,3 --controller remote

## Execution

Commands:
pingall
iperf

## Expected Output

- pingall → 0% packet loss
- iperf → throughput output
- Flow rules installed dynamically
- Failure scenario shows packet loss

## Observations

Initially packets are flooded. The controller learns MAC addresses and installs flow rules, improving efficiency.

## Proof

Screenshots included:
- pingall
- iperf
- flow table
- failure case
