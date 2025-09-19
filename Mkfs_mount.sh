#!/bin/bash
set -e

PARTITION=/dev/sdb2
MOUNT_POINT=/mnt/usb

echo "[*] Unmount & remove old modules"
# Unmount and remove modules if they exist, ignoring errors.
umount $MOUNT_POINT 2>/dev/null || true
rmmod pxt4 2>/dev/null || true
rmmod jbd3 2>/dev/null || true

echo "[*] Make fresh filesystem on $PARTITION"
# Create a new ext4 filesystem on the partition.
mkfs.ext4 -F -O ^has_journal $PARTITION

echo "[*] Load custom kernel modules"
# Load custom jbd3 and pxt4 modules.
cd jbd3
insmod jbd3.ko
cd ..
insmod pxt4.ko

# echo "[*] Disable the journaling feature"
# sudo tune2fs -O ^has_journal /dev/sdb2

# echo "[*] Force a filesystem check"
# sudo e2fsck -fy /dev/sdb2

echo "[*] Mount $PARTITION to $MOUNT_POINT" with noatime option
# Mount the partition with pxt4 type and the noatime option to disable atime updates.
mount -t pxt4 -o noatime $PARTITION $MOUNT_POINT

echo "[*] Remove lost+found and create syslab directory"
# Remove the default lost+found directory and create a test directory.
rm -rf $MOUNT_POINT/lost+found
mkdir $MOUNT_POINT/syslab

echo "[*] Done!"
