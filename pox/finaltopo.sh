#!/bin/sh

sudo mn --custom ~/mininet/custom/topo-2sw-2host.py  --topo mytopo --mac --switch ovsk --controller remote
