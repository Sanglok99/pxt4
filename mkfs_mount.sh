#!/bin/bash
set -e

PARTITION=/dev/sdb1
MOUNT_POINT=/mnt/usb

echo "[*] Unmount & remove old modules"
umount $MOUNT_POINT 2>/dev/null || true
rmmod pxt4 2>/dev/null || true
rmmod jbd3 2>/dev/null || true

echo "[*] Make fresh filesystem on $PARTITION"
mkfs.pxt4 $PARTITION -F

echo "[*] Load modules"
cd jbd3
insmod jbd3.ko
cd ..
insmod pxt4.ko

echo "[*] Mount $PARTITION to $MOUNT_POINT"
mount -t pxt4 $PARTITION $MOUNT_POINT

echo "[*] Done!"

