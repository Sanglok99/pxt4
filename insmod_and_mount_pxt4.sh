#!/bin/bash
set -e

cd jbd3
insmod jbd3.ko
cd ..
insmod pxt4.ko
mount -t pxt4 /dev/sdb1 /mnt/usb
