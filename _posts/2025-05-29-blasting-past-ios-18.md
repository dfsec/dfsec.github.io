---
layout: post
title: Blasting Past iOS 18
date: 2025-05-30 10:20
categories: ios
---

In iOS 14 and 15 Apple shipped several iOS kernel mitigations that drastically changed iOS exploitation, and many researchers documented these mitigations publicly. In iOS 17 and 18, Apple introduced several interesting iOS userspace mitigations, however they were not discussed in as much detail. In this blog post we'll discuss some of these mitigations by using the BLASTPASS exploit as a case study, and explore how relevant these exploit primitives are in iOS 18. 

BLASTPASS has been documented thoroughly by Ian Beer in his [P0 blogpost](https://googleprojectzero.blogspot.com/2025/03/blasting-past-webp.html), and we recommend reading Ian's blog post before continuing here.

# BLASTPASS Recap

```

[ Huffman Table ] -> [ Heap Metadata ] -> [CFSet Backing Buffer]--XXX-> [ LEGIT CFObject ]
                                                     |
                                                     |
                                                     +----------------> [ FAKE CFReadStream ]
                                                                             |
                                                                             +----> 0x414141414

```

The above diagram is a simplified version of the exploit chain, where:

* The attackers used a 3 byte semi-controlled out-of-bounds (OOB) write vulnerability to corrupt heap metadata;
* Heap metadata corruption is used as a 2nd stage corruption to corrupt the backing buffer of a `CFSet`;
* The `CFSet` backing buffer contains a pointer to a legitimate `CFObject`, which is corrupted to point to a fake `CFReadStream` object;
* `CFRelease` is called on the fake `CFReadStream` object to start a JOP chain;
* Code execution is accomplished.

The two key primitives the attackers used are: 

* The ability to corrupt heap metadata via an OOB write vulnerability;
* The ability to `CFRelease` a fake `CFObject`.

Let’s see how these hold up in iOS 18.

# iOS Heap Primer

In iOS 16 the libmalloc sources contained multiple allocators, which included `NanoV1`, `NanoV2`, `ScalableZone`, and some debug only allocators like `SanitizerMalloc`. At the time, iOS devices only used `NanoV2` and `ScalableZone`. 

## NanoV2

The NanoV2 allocator was shipped in libmalloc around 2018 (iOS 12), and was only meant for allocations in the size range 16 &ndash; 256 bytes. Although it is a fairly recent allocator, it has always used a static heap base:

| Platform  |	Heap Base  		|
|-----------|-------------------|
|	iOS 16	|  0x280000000 		|
|	iOS 17	|  0x280000000 		|
|	iOS 18	|  0x300000000 		|
|	macOS	|  0x600000000000 	|

The NanoV2 allocator is outside of the scope of this post, however is worth mentioning as it is still used in iOS 18.

## Scalable Zone Allocator

The Scalable Zone allocator is one of the main allocators used in some processes, even on iOS 18, and its [foundational code base](https://github.com/apple-oss-distributions/Libc/blob/Libc-583/gen/magazine_malloc.c) was published in 2009. This allocator splits allocations into `tiny`, `small`, and `large` regions based on the size of the allocation. 

The `tiny` range is used for allocations of `512 (0x200)` bytes and smaller. In this range, each region is laid out as a heap, followed by a header block. These regions are a fixed size of 1MiB.
```c
typedef struct tiny_region
{
    tiny_block_t blocks[NUM_TINY_BLOCKS];

    region_trailer_t trailer;
    
    // The interleaved bit arrays comprising the header and inuse bitfields.
    // The unused bits of each component in the last pair will be initialized to sentinel values.
    tiny_header_inuse_pair_t pairs[CEIL_NUM_TINY_BLOCKS_WORDS];
    
    uint8_t pad[TINY_REGION_SIZE - (NUM_TINY_BLOCKS * sizeof(tiny_block_t)) - TINY_METADATA_SIZE];
} *tiny_region_t;
```

The `small` range is used for allocations of `15360 (0x3c00)` bytes and smaller. In this range, each region is laid out as a heap, followed by a metadata array. These regions are a fixed size of 8MiB.
```c
typedef struct small_region
{
    small_block_t blocks[NUM_SMALL_BLOCKS];

    region_trailer_t trailer;
    
    msize_t small_meta_words[NUM_SMALL_BLOCKS];
    
    uint8_t pad[SMALL_REGION_SIZE - (NUM_SMALL_BLOCKS * sizeof(small_block_t)) - SMALL_METADATA_SIZE];
} *small_region_t;
```

The source code provides various helper macros to access different information via the allocation `ptr` for each allocator size. For the scope of this write-up we are interested in the `small` range, which provides macros to look up the region and metadata.

```c
/*
 * Locate the heap base for a pointer known to be within a small region.
 */
#define SMALL_REGION_FOR_PTR(_p)	((void *)((uintptr_t)(_p) & ~((1 << SMALL_BLOCKS_ALIGN) - 1)))

/*
 * Locate the metadata base for a pointer known to be within a small region.
 */
#define SMALL_META_HEADER_FOR_PTR(_p)	(((small_region_t)SMALL_REGION_FOR_PTR(_p))->small_meta_words)

/*
 * Compute the metadata index for a pointer known to be within a small region.
 */
#define SMALL_META_INDEX_FOR_PTR(_p)	(((uintptr_t)(_p) >> SHIFT_SMALL_QUANTUM) & (NUM_SMALL_CEIL_BLOCKS - 1))

/*
 * Find the metadata word for a pointer known to be within a small region.
 */
#define SMALL_METADATA_FOR_PTR(_p)	(SMALL_META_HEADER_FOR_PTR(_p) + SMALL_META_INDEX_FOR_PTR(_p))
```

If we dump the `vmmap` output of any process using scalable allocator, we see that these memory regions are laid out adjacent to each other:

```
REGION TYPE                    START - END         [ VSIZE  RSDNT  DIRTY   SWAP] PRT/MAX SHRMOD
...
MALLOC_SMALL                133800000-134000000    [ 8192K  8192K  8192K     0K] rw-/rwx SM=PRV
MALLOC_SMALL                134000000-134800000    [ 8192K  8192K  8192K     0K] rw-/rwx SM=PRV
MALLOC_SMALL                134800000-135000000    [ 8192K  8192K  8192K     0K] rw-/rwx SM=PRV
MALLOC_SMALL                135000000-135800000    [ 8192K  8192K  8192K     0K] rw-/rwx SM=PRV
MALLOC_SMALL                135800000-136000000    [ 8192K  8192K  8192K     0K] rw-/rwx SM=PRV
MALLOC_SMALL                136000000-136800000    [ 8192K  8192K  8192K     0K] rw-/rwx SM=PRV
MALLOC_SMALL                136800000-137000000    [ 8192K  8192K  8192K     0K] rw-/rwx SM=PRV
MALLOC_SMALL                137000000-137800000    [ 8192K  8192K  8192K     0K] rw-/rwx SM=PRV
```

If we consider the fact that there are no guard pages among these regions, the layout would look like so:

```
                                    +-------------------------+
                                    |                         |
+--------------------------------------------+  +----------------------------------------------+
 ... [block] [block] [block] [huffman table] |  | [trailer] [meta words] ... [block] [block] ...
+--------------------------------------------+  +----------------------------------------------+

```

An example of the information retrieved from metadata is as follows:
```c
/*
 * Determine whether a pointer known to be within a small region points to memory which is free.
 */
#define SMALL_PTR_IS_FREE(_p)		(*SMALL_METADATA_FOR_PTR(_p) & SMALL_IS_FREE)

/*
 * Extract the msize value for a pointer known to be within a small region.
 */
#define SMALL_PTR_SIZE(_p)		(*SMALL_METADATA_FOR_PTR(_p) & ~SMALL_IS_FREE)
```

Here we can see that attacking the heap metadata for each region (e.g. corrupting `SMALL_IS_FREE` state or the `msize` value) makes the scalable zone allocator a very interesting target; and that's what the attackers did. 

Next, we can investigate how well things hold up in terms of linear and semi-linear heap metadata corruption in iOS 18.

## XZone Allocator

Apple introduced a new allocator in iOS 17.0 beta 1 called XZone Malloc (also abbreviated as XZM). Unlike the previous ancient allocator we discussed, this allocator was designed with security in mind. It's not just meant to serve some of the most critical 0-click attack surfaces on iOS, but also Exclaves, DriverKit, and more. It seems to be heavily inspired by the kernel heap mitigations introduced in iOS 14 and 15. Unfortunately, xzone code is stripped from [public libmalloc sources](https://github.com/apple-oss-distributions/libmalloc/tree/libmalloc-657.80.3/src/xzone). Some of XZM's key features include: 

* Heap separation (`data` and `pointers`);
* OOL heap metadata;
* And type segregation.

From the perspective of BLASTDOOR exploitation, we only care about OOL heap metadata. However, we need to learn about some XZM terminology before continuing.

### Segments Groups

XZM has four different kinds of segment groups: `data`, `data_large`, `pointer_xzones`, and `pointer_large`. As their name suggests. they seem to be classified among allocation types (pointer & data, very similar to kernel's `KHEAP_DEFAULT` and `KHEAP_DATA_BUFFERS` heaps), along with some size based classification with regard to the `_large` group prefix.

Note that macOS and iOS set up segment group ranges quite differently, as per `xzm_main_malloc_zone_init_range_groups`.

### Segments

XZM segments consists of two different VM maps: a segment `body`, and a metadata `slab`. The segment body on iOS seems to be 4MiB in size, whereas the metadata slab appears to be 512KiB.

### Chunks

Chunks are groups of one or more memory pages (known as `slices` in XZM terms). XZM defines at least 8 types of chunks:

| chunk	name	  		 		| xzcb_kind	| chunk size 	|
|-------------------------------|-----------|---------------|
| XZM_SLICE_KIND_SINGLE_FREE	|	1		|	   -	 	|
| XZM_SLICE_KIND_TINY_CHUNK		|	2		|	0x4000	 	|
| XZM_SLICE_KIND_MULTI_FREE		|	3		|	   -		|
| XZM_SLICE_KIND_MULTI_BODY		|	4		|	   -		|
| XZM_SLICE_KIND_SMALL_CHUNK	|	5		|	0x10000	 	|
| XZM_SLICE_KIND_LARGE_CHUNK	|	6		|	   -		|
| XZM_SLICE_KIND_HUGE_CHUNK		|	7		|	   -		|
| XZM_SLICE_KIND_GUARD			|	8		|	0x4000		|

Chunk sizes are variable in some cases, ie. with `large` and `huge` chunks. Chunks are carved out of the segment body and follow a specific xzone ID, so a chunk can only have allocations (aka `blocks`) of the same size and same bucket ID (discussed later). Whenever a tiny or small chunk is requested, the allocator randomly maps `XZM_SLICE_KIND_GUARD` guard pages between these chunks.

# OOL Heap Metadata

Using this completely new allocator, Apple moved all of the chunk metadata out of the segment body and into the metadata slabs. XZM uses a different `mask` when mapping segment body and metadata slab allocations to keep them away from each other, preventing metadata corruption via heap OOB write vulnerabilities.

Going back to BLASTPASS, we see that heap metadata corruption using this bug is not possible anymore. We could consider a different corruption victim, however this is a bit harder now; thanks to type segregation provided by XZM.

# Type Segregation

XZM introduces type segregation for allocations on the iOS heap by implementing memory bucketing. This bucketing works such that `chunks` are tied to a specific bucket ID. The number of pointer buckets varies across devices, but can also be controlled by environment variables.

## Type ID

Unlike the iOS Kernel, we don't have dedicated `kalloc_type` structures for each allocation. Instead, all of the information for a specific object is stored in an 8-byte `malloc_type_id_t`, and is used at every `*alloc()` call site. Here's what a `malloc_type` call site looks like:

```c
MOV             X1, #0x1010040539B097A ; type_id
MOV             W0, #0x830 ; size
BL              _malloc_type_malloc
```

Most of the `type_id` bits mean something, but only the following bits seem to contribute in type segregation:

```

                        42:43 (type kind)
                          ^
                          |
                    0x1010040539B097A
                      ---    ----------> 0:31 (hash)
                      |
                    48:56 (data bits) 

```

## Bucketing

A type ID's `hash`, `type kind`, and `data bits` determine the bucket ID an allocation belongs to.

Bits 48:56 describe the structure of an allocation. If bit 56 is set and bits 48:55 are unset, it's a `data` allocation. Otherwise, it's a `pointer` allocation. `data` allocations are meant to be tied down to `data` segments, which are not supposed to contain any `pointer` chunks. If a type ID is marked as a `data` allocation, it's supposed to be locked down to bucket ID 0.

Bits 42 and 43 define the `type kind` of the allocation; ie. a C, C++, Obj-C or a Swift object. If a type ID describes the `type kind` as `Obj-C`, then the allocation is locked down to bucket ID 1. These two cases are the only scenarios where you can statically determine which xzone an allocation belongs to.

For other allocations, the bucket ID is determined at runtime using the `hash` component of the type ID.

Note: when we talk about bucketing, we generally talk about small and tiny chunks. Type segregation works differently for large chunks, and is completely disabled for huge chunks.

## Bucket Randomness

On app/daemon launch, the [kernel computes a sha256 hash](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_exec.c#L6354) called the `executable_boothash` (also known as `bucketing key` in XZM terms). Based on the number of pointer buckets, the bucketing key is then computed with the `hash` part of the type ID, and a bucket ID is determined. Thus, we can't predict a specific type ID to always get assigned to a determined bucket ID, as `executable_boothash` differs between device boots. 

The kind of allocation the huffman table's type ID defines is left as an exercise for the reader.

## Malloc Type Weakness

If library developers are not completely aware of how to implement malloc type correctly, it could lead to malloc type not being as effective as intended. For example, the C++ `operator new` is meant to allocate different C++ objects, but from the same call site. Therefore, Apple added dynamic type ID generation in the function:

```c
// __Znwm / operator new(size_t __sz):

...
MOV             X8, X30             // Use `LR` as diversifier
XPACI           X8                  // Strip down PAC
MOV             X20, #0xC0000000000 // C++ type_kind bits
BFXIL           X20, X8, #2, #0x20  // Generate dynamic type id
MOV             X0, X19 ; size
MOV             X1, X20 ; type_id
BL              _malloc_type_malloc
...
```

However, for all of iOS 17 there was no such measure taken for other critical call sites like CoreFoundation's `CFAllocatorAllocate` API. Apple fixed this weakness in iOS 18.0 beta 5 by introducing `CFAllocatorAllocateTyped`:

```c
// _CFRuntimeCreateInstance calculating dynamic type id for every different CFTypeID

type_id = (403 * (cf_typeid ^ 0xC9DC5)) & 0xFFFFFLL | 0xCF000000LL;
if ((*v8 & 0x10) != 0)
{
  v23 = malloc_default_zone();
  v22 = malloc_type_zone_memalign(v23, v18, v20 & 0xFFFFFFFFFFFFFFF0LL, type_id);
}
else
{
  // if ...
  v22 = CFAllocatorAllocateTyped(v13, v20 & 0xFFFFFFFFFFFFFFF0LL, type_id);
}
```

## Summarizing the Various Allocators


|	iOS version	|	Critical Processes	|  Non-Critical Processes 	|  	3rd Party		 |
|---------------|-----------------------|---------------------------|--------------------|
|	iOS 16		|	Scalable + NanoV2	|	  Scalable + NanoV2		|	Scalable + NanoV2|
|	iOS 17		|			XZM			|	  Scalable + NanoV2		|	Scalable + NanoV2|	
|	iOS 18		|			XZM			|	  Scalable + NanoV2		|	   XZM + NanoV2  |
|	iOS 18.4	|			XZM			|			???				|		XZM			 |


*Note: [Critical Processes](https://github.com/apple-oss-distributions/libmalloc/blob/13aaf4cb0a58d49bf649743e1406e64a573ad944/src/malloc_common.h#L126) mostly include processes that are frequently used in n-click chains.*

There are a lot of exceptions among different processes influenced by feature flags, environment variables, hardware, or even blacklisting in libmalloc. Therefore, it's best to check the allocator being used in your target process dynamically. In iOS 18.4, Apple made many changes to the libmalloc codebase, including features like thread caching for allocations sized `<=0x100` (also out of the scope of this blog post). However, it appears to have side effects in multiple 3rd party apps, so at the time of writing Apple explicitly force these apps to use the older NanoV2 allocator (instead of XZM) for small allocations:

```c
// __malloc_init

v47 = getprogname();
if (!_platform_strcmp(v47, "LetsGoClient")
    || (v48 = getprogname(), !_platform_strcmp(v48, "PESmobile"))
    || (v49 = getprogname(), !_platform_strcmp(v49, "DeltaForceClient"))
    || (v50 = getprogname(), !_platform_strcmp(v50, "MBS_PROD"))
    || (v51 = getprogname(), !_platform_strcmp(v51, "CitiAuthenticator"))
    || (v52 = getprogname(), !_platform_strcmp(v52, "Banco Galicia")))
{
    if ((dyld_program_sdk_at_least(0x12040000000002LL) & 1) == 0)
        malloc_nano_on_xzone_override = 2;
}
```

This concludes the heap internals part of this blog. Please note that all of the xzone terminology used in this blog is based on function names or error strings, so there may be inconsistencies once xzone sources are made public.

# CoreFoundation Shenanigans

The attackers are able to start a JOP chain by calling `CFRelease` on a fake `CFReadStream` object. This JOP technique relies on the fact that whenever the reference count of a `CFObject` is about to become 0, it tries to call the `finalize` routine of that specific `CFObject`. If you control the body of a `CFReadStream` object, then `CFReadStream`'s `finalize` routine gives you access to a controlled BLRAAZ. The attackers used this primitive to gain code execution.

Let’s look at the structure of a `CFObject`, and how they are able to fake it:

```c

    +0x0                    +0x8            +0xC          +0x10
    +-----------------------+---------------+-------------+
    |          ISA          |     CFInfo    |      RC     |
    +-----------------------+---------------+-------------+

```

An important note here is that the ISA pointer is PAC-authenticated. How could the attackers fake it without a heap info leak? Unlike Obj-C objects, CF objects don't necessarily use the ISA at `+0x0`, so it was possible to set the ISA to zero and use CF APIs on these CFObjects without issue. The very next 8 bytes after the ISA (`CFInfo`) describe the `CFObject`, so forging a `CFObject` out of thin air was possible.

Apple added an ISA check in `CF_IS_OBJC`, which has over 300 cross-references in different CF APIs. We will simply crash if we try to use `CFRelease` on a `CFObject` with a NULL ISA:

```
    ...
    Application Specific Information:
    CF objects must have a non-zero isa


    Thread 0 name:   Dispatch queue: com.apple.main-thread
    Thread 0 Crashed:
    0   CoreFoundation                	       0x197dad128 CF_IS_OBJC.cold.1 + 16
    1   CoreFoundation                	       0x197ce8504 CF_IS_OBJC + 296
    2   CoreFoundation                	       0x197ce8394 CFRelease + 60
    ...
```

Things don't end here, as Apple modified the `__CFRuntimeBase` structure in 17.0 beta 5 to reduce the reference count field to just 2 bytes. This gives them enough space to place a 3 byte data PAC signature for the `CFTypeID` during initialization of CFObjects:

```c

    +0x0                    +0x8       +0xB       +0xE    +0x10
    +-----------------------+----------+----------+-------+
    |          ISA          |  CFInfo  |    PAC   |   RC  |
    +-----------------------+----------+----------+-------+

```

The signature generation excludes the sub-type ID byte, which is used to define whether an object is mutable, non-mutable, etc. This signature is checked in a lot of places in CoreFoundation, including right before the `finalize` call inside of `CFRelease`. Therefore, it's no longer possible to call the `finalize` routine from a fake `CFObject`.

That concludes our investigation of the two main exploit primitives used in the iOS 16 BLASTPASS chain. Due to Apple's mitigations, both of these primitives are no longer viable.

# Honorable Mention: Harder Sandboxing

Although we don't know how the attackers proceeded with the exploit chain after getting code execution in `MessagesBlastDoorService`, it is certain that any kind of iOS attack is done by researching the target daemon's capabilities. This includes file system access, kernel attack surface access, userspace pivot access, and so forth. The sandbox profile (governed by the kernel's `Sandbox.kext`) dictates this access, and we saw in iOS 18.4 that Apple started shipping much stricter sandbox profiles with very selective access to kernel APIs.

Apple also made some major architectural changes to one of the most attacked sandbox escape daemons on iOS, `mediaserverd`. It acted as a great victim for a usermode pivot because of how much kernel attack surface it exposed, whilst itself exposing a large attack surface (including some RCE surfaces). In iOS 17 and iOS 18, Apple split `mediaserverd` across several other daemons including `mediaplaybackd`, `cameracaptured`, `audiomxd`, `AudioConvertorService`, `airplayd`, et al. These daemons have a very strict sandbox, where Apple tried to minimise the kernel attack surface as much as possible. As such, an attacker would now need to look for vulnerabilities in very specific daemons, based on an existing n-stage userspace pivot or kernel exploit.

# Credit

We would like to thank Siddharth Aeri ([@b1n4r1b01](https://x.com/b1n4r1b01)) for writing this blog post.