# Partition Twice Recover Once

This challenge involved recovering a LUKS partition from a deleted disk image, and then decrypting the LUKS parition with a provided password.

I don't know much about working with disk partitions, so fortunately I found [this StackExchange answer](https://unix.stackexchange.com/questions/364229/recover-deleted-luks-partition) that is essentially a step-by-step guide on how to solve this problem. The steps are:

```sh
# Find offset to LUKS partition and extract it.
hexdump -C image.bin |grep LUKS
dd if=image.bin of=image.luks bs=1 skip=1048576

# Mount the LUKS partition and get the flag. This will prompt for the
# decryption password.
sudo kpartx -a image.luks
sudo cryptsetup open /dev/loop0 backup
sudo mount /dev/mapper/backup /mnt/img
cat /mnt/img/flag

# Cleanup.
sudo umount /mnt/img
sudo kpartx -d image.luks
```
