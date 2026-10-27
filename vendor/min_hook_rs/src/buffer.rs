//! Memory buffer management for MinHook-rs
//!
//! This module provides memory allocation and management functionality
//! for trampoline functions. Direct port of buffer.c, with stable unwind metadata
//! beside each 64-byte code slot (VENDORED patch 17). Function-table deletion and
//! repair run outside freezes; an error keeps the allocation intact.

use crate::error::Result;
use crate::instruction::Trampoline;
use crate::trampoline::Snapshot;
use crate::unwind::Metadata;
use std::ffi::c_void;
use std::ptr;
use std::sync::Mutex;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::SystemInformation::*;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("Buffer module only supports x86_64 architecture");

/// Size of each memory slot
pub const MEMORY_SLOT_SIZE: usize = 64;

/// Size of each memory block (page size of VirtualAlloc)
const MEMORY_BLOCK_SIZE: usize = 0x1000;

/// Max range for seeking a memory block (1024MB)
const MAX_MEMORY_RANGE: usize = 0x40000000;

/// Memory protection flags to check the executable address
const PAGE_EXECUTE_FLAGS: u32 =
    PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

/// Memory slot
#[repr(C)]
union CodeSlot {
    /// Pointer to next free slot
    next: *mut MemorySlot,
    /// Buffer data
    buffer: [u8; MEMORY_SLOT_SIZE],
}

/// A code slot and its stable, separately addressed unwind metadata.
#[repr(C)]
struct MemorySlot {
    code: CodeSlot,
    metadata: Metadata,
}

/// Retirement includes pointers an active unwinder holds to the metadata.
pub(crate) const SLOT_REACH_SIZE: usize = size_of::<MemorySlot>();

/// Memory block info
#[repr(C)]
struct MemoryBlock {
    /// Pointer to next block
    next: *mut MemoryBlock,
    /// First element of the free slot list
    free: *mut MemorySlot,
    /// Number of used slots
    used_count: u32,
}

/// Global memory buffer manager
struct BufferManager {
    /// First element of the memory block list
    blocks: *mut MemoryBlock,
}

unsafe impl Send for BufferManager {}
unsafe impl Sync for BufferManager {}

impl BufferManager {
    const fn new() -> Self {
        Self {
            blocks: ptr::null_mut(),
        }
    }

    /// Get memory block
    fn get_memory_block(&mut self, origin: *mut c_void) -> *mut MemoryBlock {
        let mut block = self.blocks;

        // SAFETY: the manager lock owns the block list; fresh VirtualAlloc
        // memory is zeroed, writable, and partitioned into complete slots.
        unsafe {
            let mut si = std::mem::zeroed::<SYSTEM_INFO>();
            GetSystemInfo(&mut si);

            let mut min_addr = si.lpMinimumApplicationAddress as usize;
            let mut max_addr = si.lpMaximumApplicationAddress as usize;

            // origin ± 512MB
            if (origin as usize) > MAX_MEMORY_RANGE
                && min_addr < (origin as usize) - MAX_MEMORY_RANGE
            {
                min_addr = (origin as usize) - MAX_MEMORY_RANGE;
            }

            if max_addr > (origin as usize) + MAX_MEMORY_RANGE {
                max_addr = (origin as usize) + MAX_MEMORY_RANGE;
            }

            // Make room for MEMORY_BLOCK_SIZE bytes
            max_addr -= MEMORY_BLOCK_SIZE - 1;

            // Look for registered blocks for a reachable one
            while !block.is_null() {
                // Ignore blocks too far
                if (block as usize) < min_addr || (block as usize) >= max_addr {
                    block = (*block).next;
                    continue;
                }

                // The block has at least one unused slot
                if !(*block).free.is_null() {
                    return block;
                }

                block = (*block).next;
            }

            // Alloc a new block above if not found
            let mut alloc = origin;
            while (alloc as usize) >= min_addr {
                alloc = find_prev_free_region(
                    alloc,
                    min_addr as *mut c_void,
                    si.dwAllocationGranularity,
                );
                if alloc.is_null() {
                    break;
                }

                block = VirtualAlloc(
                    alloc,
                    MEMORY_BLOCK_SIZE,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                ) as *mut MemoryBlock;

                if !block.is_null() {
                    break;
                }
            }

            // Alloc a new block below if not found
            if block.is_null() {
                let mut alloc = origin;
                while (alloc as usize) <= max_addr {
                    alloc = find_next_free_region(
                        alloc,
                        max_addr as *mut c_void,
                        si.dwAllocationGranularity,
                    );
                    if alloc.is_null() {
                        break;
                    }

                    block = VirtualAlloc(
                        alloc,
                        MEMORY_BLOCK_SIZE,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE,
                    ) as *mut MemoryBlock;

                    if !block.is_null() {
                        break;
                    }
                }
            }

            if !block.is_null() {
                // Build a linked list of all the slots
                let mut slot = (block as *mut u8).add(size_of::<MemoryBlock>()) as *mut MemorySlot;
                (*block).free = ptr::null_mut();
                (*block).used_count = 0;

                while (slot as usize) - (block as usize) <= MEMORY_BLOCK_SIZE - SLOT_REACH_SIZE {
                    (*slot).code.next = (*block).free;
                    (*block).free = slot;
                    slot = slot.add(1);
                }

                (*block).next = self.blocks;
                self.blocks = block;
            }

            block
        }
    }

    /// Allocate a buffer
    fn allocate_buffer(&mut self, origin: *mut c_void) -> Result<*mut c_void> {
        let block = self.get_memory_block(origin);
        if block.is_null() {
            return Err(crate::error::HookError::MemoryAlloc);
        }

        // SAFETY: get_memory_block returned an owned block with a free physical
        // slot, large enough for both the code and initialized metadata.
        unsafe {
            // Remove an unused slot from the list
            let slot = (*block).free;
            (*block).free = (*slot).code.next;
            (*block).used_count += 1;

            // SAFETY: the entire physical slot belongs to this fresh allocation;
            // zero is valid for the plain metadata fields, including its bool.
            ptr::write_bytes(slot.cast::<u8>(), 0, SLOT_REACH_SIZE);
            #[cfg(debug_assertions)]
            {
                // Fill the slot with INT3 for debugging
                ptr::write_bytes(slot as *mut u8, 0xCC, MEMORY_SLOT_SIZE);
            }

            Ok(slot as *mut c_void)
        }
    }

    /// Free a buffer
    fn free_buffer(&mut self, buffer: *mut c_void) -> Result<()> {
        if buffer.is_null() {
            return Ok(());
        }

        // SAFETY: callers release only slots this manager owns and has verified
        // unreachable. The list lock prevents concurrent reuse; failed deletion
        // returns before touching the free list or the allocation.
        unsafe {
            let mut block = self.blocks;
            let mut prev: *mut MemoryBlock = ptr::null_mut();
            let target_block = ((buffer as usize) / MEMORY_BLOCK_SIZE) * MEMORY_BLOCK_SIZE;

            while !block.is_null() {
                if (block as usize) == target_block {
                    let slot = buffer as *mut MemorySlot;
                    // No freeze is active. A failure keeps both code and table.
                    (*slot).metadata.release()?;

                    #[cfg(debug_assertions)]
                    {
                        // Clear the released slot for debugging
                        ptr::write_bytes(slot as *mut u8, 0x00, MEMORY_SLOT_SIZE);
                    }

                    // Restore the released slot to the list
                    (*slot).code.next = (*block).free;
                    (*block).free = slot;
                    (*block).used_count -= 1;

                    // Free if unused
                    if (*block).used_count == 0 {
                        if !prev.is_null() {
                            (*prev).next = (*block).next;
                        } else {
                            self.blocks = (*block).next;
                        }

                        VirtualFree(block as *mut c_void, 0, MEM_RELEASE);
                    }

                    break;
                }

                prev = block;
                block = (*block).next;
            }
        }
        Ok(())
    }

    fn restore_unwind_tables(&mut self) -> Result<()> {
        let mut block = self.blocks;
        while !block.is_null() {
            // SAFETY: the manager owns every block and its complete physical
            // slots. Free slots have no described metadata. No freeze is active.
            unsafe {
                let mut slot = block
                    .cast::<u8>()
                    .add(size_of::<MemoryBlock>())
                    .cast::<MemorySlot>();
                while slot as usize - block as usize <= MEMORY_BLOCK_SIZE - SLOT_REACH_SIZE {
                    (*slot).metadata.restore()?;
                    slot = slot.add(1);
                }
                block = (*block).next;
            }
        }
        Ok(())
    }

    /// Uninitialize only after all registrations were successfully removed.
    fn uninitialize(&mut self) -> Result<()> {
        let mut scan = self.blocks;
        while !scan.is_null() {
            // SAFETY: blocks and all physical slots remain owned until this full
            // pass succeeds. Free slots have zero/unregistered metadata.
            unsafe {
                let mut slot = scan
                    .cast::<u8>()
                    .add(size_of::<MemoryBlock>())
                    .cast::<MemorySlot>();
                while slot as usize - scan as usize <= MEMORY_BLOCK_SIZE - SLOT_REACH_SIZE {
                    if let Err(error) = (*slot).metadata.unregister() {
                        // All allocations remain owned. Repair earlier deletions
                        // before returning; a failed repair is retried before any
                        // future hook change, and no code mutation may bypass it.
                        self.restore_unwind_tables()?;
                        return Err(error);
                    }
                    slot = slot.add(1);
                }
                scan = (*scan).next;
            }
        }
        let mut block = self.blocks;
        self.blocks = ptr::null_mut();

        while !block.is_null() {
            // SAFETY: every table was deleted above, and the caller verified
            // these owned blocks unreachable before requesting destruction.
            unsafe {
                let next = (*block).next;
                VirtualFree(block as *mut c_void, 0, MEM_RELEASE);
                block = next;
            }
        }
        Ok(())
    }
}

/// Global memory buffer manager
static BUFFER_MANAGER: Mutex<BufferManager> = Mutex::new(BufferManager::new());

/// Initialize the buffer system
pub fn initialize_buffer() {
    // Nothing to do for now
}

/// Uninitialize the buffer system
pub fn uninitialize_buffer() -> Result<()> {
    BUFFER_MANAGER.lock().unwrap().uninitialize()
}

/// Repair incomplete table cleanup before any hook mutation or freeze.
pub(crate) fn restore_unwind_tables() -> Result<()> {
    BUFFER_MANAGER.lock().unwrap().restore_unwind_tables()
}

/// Find previous free region
fn find_prev_free_region(
    address: *mut c_void,
    min_addr: *mut c_void,
    allocation_granularity: u32,
) -> *mut c_void {
    let mut try_addr = address as usize;

    // Round down to the allocation granularity
    try_addr -= try_addr % allocation_granularity as usize;

    // Start from the previous allocation granularity multiply
    try_addr -= allocation_granularity as usize;

    while try_addr >= min_addr as usize {
        // SAFETY: VirtualQuery only queries mappings and writes our local record.
        unsafe {
            let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
            if VirtualQuery(
                try_addr as *const c_void,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            if mbi.State == MEM_FREE {
                return try_addr as *mut c_void;
            }

            if (mbi.AllocationBase as usize) < allocation_granularity as usize {
                break;
            }

            try_addr = mbi.AllocationBase as usize - allocation_granularity as usize;
        }
    }

    ptr::null_mut()
}

/// Find next free region
fn find_next_free_region(
    address: *mut c_void,
    max_addr: *mut c_void,
    allocation_granularity: u32,
) -> *mut c_void {
    let mut try_addr = address as usize;

    // Round down to the allocation granularity
    try_addr -= try_addr % allocation_granularity as usize;

    // Start from the next allocation granularity multiply
    try_addr += allocation_granularity as usize;

    while try_addr <= max_addr as usize {
        // SAFETY: VirtualQuery only queries mappings and writes our local record.
        unsafe {
            let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
            if VirtualQuery(
                try_addr as *const c_void,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            if mbi.State == MEM_FREE {
                return try_addr as *mut c_void;
            }

            try_addr = mbi.BaseAddress as usize + mbi.RegionSize;

            // Round up to the next allocation granularity
            try_addr += allocation_granularity as usize - 1;
            try_addr -= try_addr % allocation_granularity as usize;
        }
    }

    ptr::null_mut()
}

/// Allocate a buffer
pub fn allocate_buffer(origin: *mut c_void) -> Result<*mut c_void> {
    BUFFER_MANAGER.lock().unwrap().allocate_buffer(origin)
}

/// Free a buffer
pub fn free_buffer(buffer: *mut c_void) -> Result<()> {
    BUFFER_MANAGER.lock().unwrap().free_buffer(buffer)
}

/// Register before publication. The slot and its metadata belong to the manager.
pub(crate) fn register_unwind(ct: &Trampoline, snapshot: &Snapshot) -> Result<()> {
    let _manager = BUFFER_MANAGER.lock().unwrap();
    let slot = ct.trampoline.cast::<MemorySlot>();
    // Each table needs its own non-overlapping lookup range. Wine chooses the
    // first dynamic table whose BaseAddress..End covers the PC, even if the
    // table's entries then have no match. A block-wide base would shadow slots.
    let base = ct.trampoline as usize;
    // SAFETY: create_trampoline allocated this slot, never published or freed it.
    unsafe { (*slot).metadata.register(base, ct, snapshot) }
}

/// Check if address is executable. The address is only queried, never dereferenced.
pub fn is_executable_address(address: usize) -> bool {
    if address == 0 {
        return false;
    }

    // SAFETY: VirtualQuery never dereferences address, and mi is writable.
    unsafe {
        let mut mi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
        VirtualQuery(
            address as *const c_void,
            &mut mi,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        );

        mi.State == MEM_COMMIT && (mi.Protect & PAGE_EXECUTE_FLAGS) != 0
    }
}

/// How many trampoline slots are allocated, across every block. Test-only: lets a
/// test see that a refused hook gave its slot back.
#[cfg(test)]
pub(crate) fn used_slots() -> usize {
    let manager = BUFFER_MANAGER.lock().unwrap();
    let mut used = 0usize;
    let mut block = manager.blocks;
    while !block.is_null() {
        // SAFETY: every block in the list is a live allocation the manager owns.
        unsafe {
            used += (*block).used_count as usize;
            block = (*block).next;
        }
    }
    used
}

/// Snapshot of described tables for bulk cleanup/repair tests. Outside freezes.
#[cfg(test)]
pub(crate) fn described_tables() -> Vec<(usize, usize)> {
    let manager = BUFFER_MANAGER.lock().unwrap();
    let mut tables = Vec::new();
    let mut block = manager.blocks;
    while !block.is_null() {
        // SAFETY: the manager lock protects every owned block and physical slot.
        unsafe {
            let mut slot = block
                .cast::<u8>()
                .add(size_of::<MemoryBlock>())
                .cast::<MemorySlot>();
            while slot as usize - block as usize <= MEMORY_BLOCK_SIZE - SLOT_REACH_SIZE {
                if let Some(table) = (*slot).metadata.described_table() {
                    tables.push(table);
                }
                slot = slot.add(1);
            }
            block = (*block).next;
        }
    }
    tables
}
