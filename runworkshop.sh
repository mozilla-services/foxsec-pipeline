#!/bin/bash

bin/m compile exec:java -Dexec.mainClass=com.mozilla.secops.workshop.Workshop \
	-Dexec.args='--inputType=file --input=./target/classes/workshop.txt.gz'
