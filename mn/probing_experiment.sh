#!/bin/bash
# (c) 2021 Sohum Mendon
# This simple bash script launches the probing experiment
# 5 times, and it cleans up the leftover mininet files.

for i in {1..5}; do
	sudo python3 probing_accuracy.py experiment	
	sudo mn -c
done
