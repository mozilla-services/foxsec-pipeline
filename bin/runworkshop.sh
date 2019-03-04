#!/bin/bash

# This is a small helper script that can be used for the introduction to
# Beam workshop

bin/m compile exec:java -Dexec.mainClass=com.mozilla.secops.workshop.Workshop \
	-Dexec.args='--inputFile=./target/classes/workshop.txt.gz'
