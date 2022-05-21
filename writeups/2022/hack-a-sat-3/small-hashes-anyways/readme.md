# Small Hashes Anyways

Running the binary:

```sh
# Copy qemu binary and challenge binary into microblaze musl.cc tree:
cp $(which qemu-microblaze-static) microblaze-linux/
cp small_hashes_anyways microblaze-linux/

# Change into the microblaze-linux/ root
cd microblaze-linux/

# Repair the library load path (run these from the microblaze-linux/ root:
mkdir -p opt/cross
ln -s ../../.. opt/cross/microblaze-linux

# Running this from the microblaze-linux/ works:
sudo chroot . ./qemu-microblaze-static ./small_hashes_anyways
```

Once you can get the binary up and running, it's relatively straightforward brute force of the flag.
