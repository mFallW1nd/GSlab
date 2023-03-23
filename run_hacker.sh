#!/bin/bash
adb push ./Output/ /data/local/tmp
adb shell "su -c 'cd /data/local/tmp/Output && ./Hacker'"