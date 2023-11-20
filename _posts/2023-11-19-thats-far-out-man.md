---
layout: post
title: That's FAR-out, Man
date: 2023-11-19 17:37
categories: ios
---

In mid-2023 we noticed a kernel infoleak which led to the discovery of quite an interesting bug. The infoleak was caused by the access of an uninitialised value in the `FAR_EL1` register, which was copied unconditionally by XNU's exception handler.

## An Accidental Discovery

While this bug is buried quite deep within XNU, finding it accidentally was trivial. Under the right circumstances, userland processes on an XNU system could crash with a kernel pointer in the `far` register, which appeared in the corresponding crash log.

This bug was patched in iOS 17.1 beta 2, with the patch appearing in XNU source release `xnu-100002.41.9`.

In order to understand the bug in more detail, it's worth introducing some concepts core to arm64 CPUs.

## Exceptions

If you are familiar with object-oriented programming, you will be familiar with the concept of "exceptions". This is when an error occurs which disrupts the normal flow of the program. In the case of OOP, this could be a value being `NULL` (i.e. a "NULL reference exception"), for example. This idea of exceptions is also present at the CPU level.

Lets consider the case where an instruction tries to load a value from an invalid address:

```
ldr x0, [x1] ; X1 = 0x4141414142424242
cmp x0, x2
...
```

In this example, the `X1` register contains an invalid virtual address, so the CPU is not able to load a value from it and continue execution. Therefore, an exception must be raised. These exceptions are handled by a table of functions known as the exception table. On arm64, the address of this table is held in the register `VBAR` (Vector Base Address Register). Depending on the type of exception, different exception handlers are jumped to by the CPU.

There are two main types of exceptions, "synchronous" and "asynchronous". Synchronous exceptions are where the exception can be tied to a specific instruction. In our example, the exception is directly raised by the `ldr` instruction, hence our code will raise a synchronous exception.
Asynchronous exceptions are where the exception cannot be tied to a single instruction or point of execution. For example, this could be some external hardware raising an interrupt to the CPU. While there is only one type of synchronous exception, arm64 divides asynchronous exceptions into 3 further categories: irq (interrupt request), fiq (fast interrupt request), and serror (system error). For the purpose of this blog post we are only interested in synchronous exceptions, however it's useful to understand the various types.

Synchronous exceptions can be raised for different reasons. Our example triggers a "data abort" exception, where the CPU tries to load data from an invalid address, however this is just one of many. The arm64 manual lists over 20 synchronous exception types. Some notable examples include:

- Instruction aborts (similar to the data abort - the CPU tried to execute some memory it could not fetch from)
- PC alignment faults (all instructions must be aligned to 0x4 bytes in memory)
- Undefined instructions (the CPU tried to execute an invalid instruction)
- Supervisor calls (a piece of code wants to run code in a higher *exception level*, for example a syscall to the kernel)

It's important to note that when the CPU has faulted on a specific virtual address, the address will be copied into the per-core `FAR_ELn` register. This happens in the case of instruction and data aborts, among others, though not for all exception types. In our previous example, the value `0x4141414142424242` would be placed into `FAR_ELn`.

## Virtual Memory System Architecture (VMSA)

Previously we have referenced the idea of "virtual" memory. It's important to understand there are two "types" of memory on modern CPUs: virtual, and physical. Physical memory is the physical RAM installed in the computer or chip. RAM chips use a series of logic gates to hold the ones and zeros which represent data on a computer (the physical address space can also reference other hardware such as MMIO, but this is out of scope for this write-up). On top of this, CPUs create an abstraction layer known as virtual memory. Virtual memory allows CPUs to "create" more memory than is physically installed in the system, and be significantly more efficient with physical memory usage. Virtual memory can be "mapped" to physical memory through the use of *page tables*. Virtual memory can also be *unmapped*, or multiple virtual memory pages can be mapped to the same physical page. Virtual memory pages also have permissions, which (among other things) defines whether a page is readable, writable, executable, or a combination thereof. These page permissions are particularly useful for security reasons, and are used all throughout modern operating systems.

```
              ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐
  Virtual     │ r-x  │  │ r--  │  │ r--  │  │ rw-  │
  Memory      │      │  │      │  │      │  │      │
              └──┬───┘  └──┬───┘  └──┬───┘  └──────┘
                 │         │         │      (Unmapped)
                 │         ├─────────┘
                 │         │
              ┌──▼───┐  ┌──▼───┐
  Physical    │      │  │      │
  Memory      │      │  │      │
              └──────┘  └──────┘
```

As mentioned, these mappings between virtual and physical memory are defined by the page tables (also known as "translation tables").

Let's consider this theoretical C-code snippet:

```c
void *data = malloc(0x4000);

*(uint64_t *)data = 0x41424344;
```

In assembly:

```
movk x0, #0x4000
bl _malloc

movk x1, #0x41424344
str x1, [x0]
```

Here, the `malloc` call will return a page of virtual memory. At this point in time, the memory is "non-resident", meaning it is not backed by a physical page, and is not present in the translation tables. This serves as a memory-saving optimisation, where virtual memory is not mapped until it's used.

When we write to the buffer, the CPU will try and do a store to the address returned by `malloc`. At this point, the virtual address is not present in the translation tables, so an exception will be raised (specifically; a data abort exception). The CPU will load the faulting address into `FAR_EL1`, and jump to the exception handler table. In the case of our synchronous data abort, this will eventually end up in the kernel function `handle_user_abort`:

```c
static void
handle_user_abort(arm_saved_state_t *state, uint32_t esr, vm_offset_t fault_addr,
    fault_status_t fault_code, vm_prot_t fault_type, expected_fault_handler_t expected_fault_handler)
{
    if (is_vm_fault(fault_code)) {
        // [...]
        /* We have to fault the page in */
        result = vm_fault(map, vm_fault_addr, fault_type,
            /* change_wiring */ FALSE, VM_KERN_MEMORY_NONE, THREAD_ABORTSAFE,
            /* caller_pmap */ NULL, /* caller_pmap_addr */ 0);
        // [...]
    } else if (is_alignment_fault(fault_code)) {
        // [...]
    } else if (is_parity_error(fault_code)) {
        // [...]
    } else {
        codes[0] = KERN_FAILURE;
    }

    codes[1] = fault_addr;
    exception_triage(exc, codes, numcodes);
    __builtin_unreachable();
}
```

*(Large regions of code have been omitted for clarity)*

As you can see, the kernel will attempt to handle the fault gracefully via the VM subsystem (i.e. the `vm_fault` call). This will "map in" the page by allocating a physical page for the previously allocated virtual page, and adding the entry to the translation tables. The handler then returns to the caller, which eventually returns from the exception. Since the exception was handled successfully, the CPU will re-run the faulting instruction, and continue execution. Note that the `FAR_EL1` register where the faulting address was previously copied to is not cleared, neither by XNU's code, nor architecturally.

While this example references userland, the implementation is effectively identical for pageable memory in the kernel, too:

```c
static void
handle_kernel_abort(arm_saved_state_t *state, uint32_t esr, vm_offset_t fault_addr,
    fault_status_t fault_code, vm_prot_t fault_type, expected_fault_handler_t expected_fault_handler)
{
    if (is_vm_fault(fault_code)) {
        if (VM_KERNEL_ADDRESS(fault_addr) /* ... */) {
            map = kernel_map;
        } else {
            // [...]
        }

        if (result != KERN_PROTECTION_FAILURE) {
            /*
             *  We have to "fault" the page in.
             */
            result = vm_fault(map, fault_addr, fault_type,
                /* change_wiring */ FALSE, VM_KERN_MEMORY_NONE, interruptible,
                /* caller_pmap */ NULL, /* caller_pmap_addr */ 0);
        }

        if (result == KERN_SUCCESS) {
            return;
        }
    } else if (is_alignment_fault(fault_code)) {
        // [...]
    } else {
        // [...]
    }

    panic_with_thread_kernel_state("Kernel data abort.", state);
}
```

In the case the kernel is not able to handle a kernel fault, the kernel panics with the all too-familiar panic string, "Kernel data abort".

## The Bug

At the beginning of this post we noted how the `FAR_ELn` register is only updated for specific types of exceptions:

> It's important to note that when the CPU has faulted on a specific virtual address, the address will be copied into the per-core `FAR_ELn` register. This happens in the case of instruction and data aborts, among others, though not for all exception types.

We also just noted how this register is not cleared after one of those cases is handled:

> Note that the `FAR_EL1` register where the faulting address was previously copied to is not cleared, neither by XNU's code, nor architecturally.

There is one other interesting detail which we have skimmed over. When an exception occurs in XNU, the entire core's state is copied into the thread's data structure. This includes general register state, and exception registers such as `FAR_ELn`. This is done, presumably, in the interest of being optimally performant in hot code. This is as opposed to conditionally copying only relevant state information depending on the nature of the exception.

Lets consider the case where a core executes two faults within quick succession, perhaps with each fault occurring in a different thread and in different tasks (i.e. kernel task and a user's task):

```c
/* In kernel */
vm_offset_t address = 0x0;
kernel_memory_allocate(kernel_map, &address, 0x4000, ...);

*(uint64_t *)address = 0x41424344;

/* <-- Context switch to another thread --> */

/* Then, in userland */
__asm__("brk #1");
```

In order:
1. XNU's virtual memory subsystem returns a non-resident, unmapped page
2. The write triggers a write fault (data abort exception)
3. The address of `data` is copied to `FAR_EL1`
4. The exception is handled gracefully by XNU
5. Our core switches to executing in userland
6. We "manually" trigger an exception via a breakpoint debug instruction
7. Due to the exception type, `FAR_EL1` is **not** updated by the CPU
8. XNU copies our core's state, including the *stale `FAR_EL1`*, to our thread's data structure

This means the stale value in `FAR_EL1`, which in this case is a kernel pointer, has been incorrectly copied to our thread's data structure!

In this example the thread is owned by our own task, so we can access the exception state via the `thread_get_state` API:

```c
kern_return_t
machine_thread_get_state(thread_t                 thread,
    thread_flavor_t          flavor,
    thread_state_t           tstate,
    mach_msg_type_number_t * count)
{
    switch (flavor) {
        // [...]

        case ARM_EXCEPTION_STATE64:{
            // [...]

            state = (struct arm_exception_state64 *) tstate;
            saved_state = saved_state64(thread->machine.upcb);

            state->exception = saved_state->exception;
            state->far = saved_state->far; // returns the stale, leaked, FAR_EL1 value to the caller
            state->esr = saved_state->esr;

            *count = ARM_EXCEPTION_STATE64_COUNT;
            break;
        }

        // [...]
    }
}
```

Not only can we use this bug to leak data from the kernel, but we can actually leak data from any task on the system (assuming we can coerce the target task into triggering a memory fault).

## Improving Exploitation

If you were to run the above PoC on an XNU system, you would leak a variety of pointers, both from the kernel and other tasks. However, it's possible to leak data more accurately, under certain conditions. By coercing the target task into triggering the fault at a specific offset within the unmapped page, we can very accurately detect when the correct allocation has been leaked:

```c
/* retrieve exception state -- leaked value is in `far` */
arm_exception_state64_t exception_state = { };
mach_msg_type_number_t exception_count = ARM_EXCEPTION_STATE64_COUNT;
thread_get_state(target_thread, ARM_EXCEPTION_STATE64, (thread_state_t)&exception_state, &exception_count);

uint64_t leak_val = exception_state.__far;

if ((leak_val & (0xffffULL << 48)) == (0xffffULL << 48) /* is it in kenrel? */ &&
    (leak_val & 0x3fff) == 0x1234 /* is it at the offset we're expecting? */)
{
    *kernel_pointer = leak_val - 0x1234;
}
```

Another method of detection is to rely on the object having a pre-known size, and leaking a high number of pointers. You can then use the offset between two sequential allocations (since heap allocations are generally performed in a linear fashion), to determine if you have found the correct object.

## The Fix

Assuming performance is not a priority, there are 3 options that Apple had when fixing this bug:

1. Zero out the `FAR_EL1` register directly after reading it, when an exception (data abort & co) is handled (best option)
2. Only copy relevant registers and state data when an exception is raised (intermediate option)
3. Sanitise `far` in the saved state when an exception is raised, but only in cases where it's unused (worst option)

In typical Apple fashion, they opted for the latter:

```c
void
sleh_synchronous(arm_context_t *context, uint32_t esr, vm_offset_t far)
{
    // [...]
    /* Sanitize FAR (but only if the exception was taken from userspace) */
    switch (class) {
        case ESR_EC_IABORT_EL1:
        case ESR_EC_IABORT_EL0:
            /* If this is a SEA, since we can't trust FnV, just clear FAR from the save area. */
            if (ISS_IA_FSC(ESR_ISS(esr)) == FSC_SYNC_EXT_ABORT) {
                saved_state64(state)->far = 0;
            }
            break;
        case ESR_EC_DABORT_EL1:
        case ESR_EC_DABORT_EL0:
            /* If this is a SEA, since we can't trust FnV, just clear FAR from the save area. */
            if (ISS_DA_FSC(ESR_ISS(esr)) == FSC_SYNC_EXT_ABORT) {
                saved_state64(state)->far = 0;
            }
            break;
        case ESR_EC_WATCHPT_MATCH_EL1:
        case ESR_EC_WATCHPT_MATCH_EL0:
        case ESR_EC_PC_ALIGN:
            break;  /* FAR_ELx is valid */
        default:
            saved_state64(state)->far = 0;
            break;
    }
    // [...]
}
```

```c
void
sleh_serror(arm_context_t *context, uint32_t esr, vm_offset_t far)
{
    // [...]
    if (PSR64_IS_USER(get_saved_state_cpsr(state))) {
        /* Sanitize FAR (only if we came from userspace) */
        saved_state64(state)->far = 0;
    }
    // [...]
}
```

*(Again, code has been omitted for clarity)*

This fix, whilst making the bug unexploitable (since you can no longer access the stale `far` value via the kernel's APIs), does not patch the root cause: *`FAR_ELn` should not be left stale (fix #1), and should not be copied unconditionally (fix #2), by the exception handler.*
