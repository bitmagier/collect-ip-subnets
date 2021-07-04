#!/bin/bash

sudo journalctl -x --since="-6months"|grep Blocking | awk '{ print $7 };'|sed -e 's/"//g'|sed -e 's/\/32//g'
