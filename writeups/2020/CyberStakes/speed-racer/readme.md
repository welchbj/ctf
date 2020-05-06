# Speed Racer

This was one of the higher point binary exploitation challenges, and involved exploiting a write-after-free vulnerability to create a fake racer object.

## Understanding the Binary

The program is actually fairly simple once you get some of the preliminary reverse engineering out of the way. It is a "racer" management system, with functionality for creating, updating, and printing information about each of the racers in the system. Each racer has a few different fields, to include things like its racer number, number of passengers, name, color, and description. Each racer is formed from a `malloc` allocation of `0x50` bytes, with its name being stored in another `malloc`ed piece of memory of user-controlled length.

The list of racers is managed as a singly-linked list, with the head of the list being stored in a global variable. Accesses to the list head are protected with a global mutex. Each racer contains a pointer to the next racer in the list, with a `NULL` next pointer indicating the end of the list.

Interacting with the server is done via a network connection, which will spawn a new thread to service the connection. Your client connection then needs to specify the opcode corresponding to what it wants to do, which might be one of:

* Create a new racer.
* Print information about an existing racer.
* Update an existing racer.
* Free an existing racer.
* Run a race between the existing racers (don't know much about this one since it's not needed for exploitation).
* Shutdown the entire server (also not needed for exploitation).

A crucial detail for each of these operations is that the racer on which to perform the selected action is chosen by its user-specified racer number. Each of these operations begins by accepting a user-specified racer number and then iterates over the singly-linked racer list until finding the racer with the corresponding racer number. This is an important detail later on.

Of note is that the binary will ensure it is run with a single arena, via the [`MALLOC_ARENA_MAX` environment variable](https://devcenter.heroku.com/articles/tuning-glibc-memory-behavior). This makes multi-threaded heap-based exploitation more manageable.

## Vulnerability Discovery

Due to the racing theme, it became pretty obvious that a race condition would be involved in the exploitation at some point. This allows us to focus our search on uses of the global mutex, which is meant to prevent concurrent access to the global racer list.

The mutex is used safely in all of the functionality, except for a fatal flaw in the racer-creation logic. Let's start by looking at Ghidra's decompilation of the racer creation code:

```c
  malloced_racer = (undefined8 *)malloc(0x50);
  if (malloced_racer == (undefined8 *)0x0) {
    close(param_1);
                    /* WARNING: Subroutine does not return */
    pthread_exit((void *)0x0);
  }
  memset(malloced_racer,0,0x50);
  pvVar2 = malloc((ulong)local_ac);
  *(void **)(malloced_racer + 8) = pvVar2;
  if (malloced_racer == (undefined8 *)0x0) {
    close(param_1);
                    /* WARNING: Subroutine does not return */
    pthread_exit((void *)0x0);
  }
  pthread_mutex_lock((pthread_mutex_t *)&GLOBAL_MUTEX);
  *(undefined8 **)malloced_racer = RACER_LIST_HEAD;
  RACER_LIST_HEAD = malloced_racer;
  pthread_mutex_unlock((pthread_mutex_t *)&GLOBAL_MUTEX);
  malloced_racer[2] = local_a8;
  *(undefined *)(malloced_racer + 9) = local_ad;
  dVar3 = FUN_00400fb1(local_78);
  *(double *)(malloced_racer + 1) = dVar3;
  strncpy((char *)(malloced_racer + 3),local_98,0x10);
  strncpy((char *)(malloced_racer + 5),local_88,0x10);
  *(uint *)(malloced_racer + 7) = local_ac;
  // The mutex is no longer acquired at this point, but the program will block
  // on this read until we send it the racer description.
  read(param_1,(void *)malloced_racer[8],(ulong)local_ac);
```

At first glance, the mutex seems to be properly acquired for all of the operations that affect the global racer list head variable. However, the program continues to write to the racer's description after the hold on the mutex has been released. Since this write comes in the form of a `read` from `stdin`, we can make it block at this point for an indefinite period of time, as long as we keep our client connection open.

Imagine that, while this connection blocks on the `read`, we open a new connection to free the racer we had just created. Since the mutex is no longer held by the creation connection, the program will gladly free both the chunk `malloc`ed for the racer and the chunk `malloc`ed for its decription. This means that our original racer-creation connection will be writing to a now-freed chunk!

Now, with the first racer having been freed, we can try to create two new racers at the exact same moment in time. Our goal is that one of their racer `malloc` requests will be serviced with the chunk that our original `read` is still writing into. We can then finish sending data to the original racer-creation thread (which is still blocking on a `read`), which can then overwrite the entirety of one of the allocated racers.

An important note: we must ensure that we close the connection that triggered the free. Otherwise, the freed chunk will remain in that thread's tcache, where it can never be used to service an allocation request for a different thread. With this thread closed, the chunk will graduate to a fastbin, where it can service an incoming `malloc` request of the appropriate length.

## Exploitation

This single vulnerability we discovered is sufficient to create an information leak and achieve code execution.

The information leak, which we'll use to find the address of a known function in the target's loaded libc, is fairly straightforward. Since the racer struct contains a pointer to its description string buffer, we can make a fake racer that overwrites this pointer address to the address of a GOT table entry. Printing this racer through the application's organic racer-printing functionality will leak the address of the loaded function when printing the racer's description string. It's important to note that we know the GOT entry address with certainty because the binary does not have PIE enabled. Knowing the loaded address of a function in libc, and having been provided the [target's libc](./libc.so), we can derive the loaded libc base address and, consequently, the loaded address of any libc function.

Gaining code execution from a fake racer is surprisingly elegant, too. To do this, we'll be abusing the next pointer present in the racer struct, which is used to implement the singly-linked list of racers. Let's first take a look at Ghidra's decompilation of the racer-updating code:

```c
  racer_ptr = RACER_LIST_HEAD;
  while ((racer_ptr != (undefined8 *)0x0 && (*(char *)(racer_ptr + 9) != idx_to_update))) {
    racer_ptr = (undefined8 *)*racer_ptr;
  }
  if (racer_ptr != (undefined8 *)0x0) {
    n = read(param_1,&field_to_update_idx,4);
    if (n != 4) {
      pthread_mutex_unlock((pthread_mutex_t *)&GLOBAL_MUTEX);
      close(param_1);
                    /* WARNING: Subroutine does not return */
      pthread_exit((void *)0x0);
    }
... snip ...
    if (field_to_update_idx == 1) {
      n = read(param_1,racer_ptr + 2,8);
      if (n != 8) {
        pthread_mutex_unlock((pthread_mutex_t *)&GLOBAL_MUTEX);
        close(param_1);
                    /* WARNING: Subroutine does not return */
        pthread_exit((void *)0x0);
      }
    }
```

We can see that the program attempts to find which racer to update only based on the racer number that we provide. In its search for the racer with the corresponding number, the program continuously dereferences the current racer's next pointer until it encounters a null pointer. Consider what would happen if we updated our fake racer's next pointer to point somewhere around where the GOT entries are stored in the binary. If we were able to provide the correct racer number that corresponds to wherever we land in the GOT entries, then it's possible to start writing data there.

Looking further down in the above decompilation, we see that we have the ability to write 8 arbitrary bytes to a position 2 qwords away from the racer pointer. Let's say we want to target the `free` GOT entry, which sits at address `0x603020`. If we forge our fake racer's next pointer to be `free@GOT - 0x10 == 0x603010`, then the program will overwrite `free@GOT` with 8 bytes from `stdin`. For exploitation, we'll pick the 8 bytes that represent the loaded address for `system@libc` (computed via our information leak). We then just need to `free` a string which holds the command we want to execute; this can easily be achieved using other paths in the program's racer-updating functionality.

There is one piece missing, though: to make the update code actually act on our forged next racer pointer, we need to pick the racer number that corresponds to the byte in the binary at `free@GOT - 0x10 + 0x48` (which mimics how a real racer's number is pulled from the struct base address). This turns out to be the byte `0x26`, which can be derived from static analysis of the binary or debugging.

So, in the end, we only need to exploit the program's vulnerability one time to set the conditions for our information leak and eventual code execution. You can find this all implemented in [my solve script](./solve.py).
