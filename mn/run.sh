#!/bin/bash
# (c) 2021 Sohum Mendon
# A script that automatically launches an interactive Mininet instance.

PROJECT_PATH="/home/mininet/rigel-sdn-dos/mn"

sudo --preserve-env mn \
	--wait \
	--xterms \
	--mac \
	--switch=ovsk \
	--custom=$PROJECT_PATH/topo-2sw-3host.py \
	--topo=testbedtopo \
	--controller=ryu,$PROJECT_PATH/simple_switch_14.py,ryu.app.ofctl_rest
