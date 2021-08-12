#!/bin/bash
if [ "$EUID" -ne 0 ] ;
	echo "Run as Root"
	exit
fi