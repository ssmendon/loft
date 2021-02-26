# Denial of Service in Software-Defined Networks

## Installation

To mess around with the code, we need to set up the proper environment. Our team used the [Mininet reference VM](hhttps://github.com/mininet/mininet/releases/tag/2.3.0b2) in VirtualBox on Ubuntu 20.04. We recommend installing that VM image and using VirtualBox to launch it. There is a bug in the latest 2.3.0 VM image that forces a different set-up.

You'll need to configure X11 forwarding if you want to be able to launch applications like Wireshark and xterm, which we rely on to run the interactive experiment files. There are tons of resources for X11 forwarding, and here is [a link in Mininet's documentation about how it works](https://github.com/mininet/mininet/wiki/FAQ#x11-forwarding).

You'll want to clone the repository in the mininet user's home directory with `git`. All the files are set up expecting that mininet will be launched in the home directory.

You'll also need to install the dependencies. There's the Python dependencies in `requirements.txt` that can be installed with `python3 -m pip install -r requirements.txt` or `pip3 install -r requirements.txt` both as mininet and as root. You'll also need to install the controller Ryu using `sudo apt install python3-ryu`. You'll also need to install `tcpreplay`.

## Running

Take a look at our demo video to see how the code can be used. If you want to probe the idle timeouts, you can run `./probing_experiment.sh`. This will launch a Mininet network using the `simple_switch_14.py` file's hard and idle timeouts. It will run the experiment 5 times, saving the results to a file `~/results.csv`.

To launch the attack experiment, use `run.sh` to start a Mininet network. On the controller's xterm, launch the `controller.py` script. This script periodically polls a switch for flow information. On the benign host's xterm (not the server) launch the `networkG.py` script. This file creates 25 benign network flows as background noise. Finally, on the attacker, launch the `experiment.py` script. This will initiate the attack. You can use `iperf` to measure the throughput and `ping` to measure the network latency while the attack is going on.

## Credits
- attack.py was made by Hongquy and it launches an attack using DoS
- controller.py was made by Hongquy and it regularly queries the OpenFlow controller for flow information
- experiment.py was made by Hongquy and it launches the probing then attack sequence against the server
- networkG.py was made by Hongquy and it generates benign traffic with Scapy
- probe.py was made by Sohum and it performs the field, hard timeout, and idle timeout probing
- probing_accuracy.py was made by Sohum and it helps with the probing experimental validation
- probing_experiment.sh was made by Sohum and it launches the probing validation 5 times
- run.sh was made by Sohum and it launches the Mininet environment
- ryu.py was made by Sohum and it connects to the controller's REST API
- simple_switch_14.py was edited by Sohum and it has the simple learning switch behaviors and allows for idle and hard timeouts
- topo-2sw-3host.py was edited by Sohum and it creates the custom network topology
