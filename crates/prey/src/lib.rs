//! # Prey
//! _Proxy Reverse Engine Yield_
//!
//! This is the core of the whole framework
//! By now, contains buffer management and recycling.
//! > **Its still under development**
//!
//! ## Buffer Management
//! The way PREY deals with buffers is simple but smart:
//! It allocates space once, and all the remaining management is done by
//! itself. This makes PREY really efficient in terms of speed while dealing
//! with memory, since it does not need to depend on kernel and OS services during
//! its runtime, only at its start.
//!
//! It uses an efficient memory layout to prevent unnecessary space allocation,
//! using cache lines fixed on 64 bits per line.
//!
//! Buffers have a fixed size of 2048 bytes, but they aren't fully filled with
//! information. Since normal Network packets does not exceed 1500 bytes of length
//! PREY buffers will be able to contain all packets' info and still be able to
//! add new data to it, without the need to expand the buffer size.

use std::alloc::{alloc, Layout};
use std::sync::Arc;
use crossbeam_queue::ArrayQueue;
//Commom max cache line value used by CPUs
const CACHE_LINE: usize = 64;

//Size of buffers used in prey
const BUFFER_SIZE: usize = 2048;

/// # Buffer
/// Struct that contains the main buffer structure of the PREY framework.
/// ## Fields
/// - ptr: `*mut u8` - Pointer to the root of the buffer.
/// - capacity: `usize` - Total capacity of the buffer (2048 bytes).
/// - head: `usize` - Offset to actual start of useful data in buffer (128 bytes).
/// - size: `usize` - Size of useful data in buffer.
/// - pool: `Arc<BufferPool>` - Reference to parent buffer pool.
pub struct Buffer {
    ptr: *mut u8,
    capacity: usize,
    head: usize,
    size: usize,
    pool: Arc<BufferPool>
}

impl Drop for Buffer {
    //Implements drop trait for Buffer struct, to override default behavior
    // stopping the complete release of buffer memory area, and simply returning
    // its control back to the buffer pool.
    fn drop(&mut self) {
        let _ = self.pool.available.push(self.ptr);
    }
}

/// # BufferPool
/// structure that holds all the space buffers will need.
///
/// ## Fields
/// - storage: `*mut u8` - Reference to the start of allocated memory area.
/// - capacity: `usize` - Total size of Buffer Pull memory area.
/// - available: `ArrayQueue<*mut u8>` - Array that holds all buffer sections start points.
pub struct BufferPool {
    storage: *mut u8,
    capacity: usize,
    available: ArrayQueue<*mut u8>
}

impl BufferPool {
    /// # fn new
    /// Function that creates a new BufferPool.
    ///
    /// # Params
    /// - num_buffers: `usize` - Number of buffers that will exist in the pool.
    ///
    /// # Returns
    /// A `Arc` reference to a new BufferPool, with 100MB of memory already allocated.
    pub fn new(num_buffers: usize) -> Arc<Self> {
        let total_size = num_buffers * BUFFER_SIZE;
        let layout = Layout::from_size_align(total_size, CACHE_LINE).expect("Falha ao definir layout da pool na memória.");

        let storage = unsafe { alloc(layout) };
        let available = ArrayQueue::new(num_buffers);

        for i in 0..num_buffers {
            unsafe {
                let buffer_ptr = storage.add(i * BUFFER_SIZE);
                let _ = available.push(buffer_ptr);
            }
        }


        Arc::new(Self {
            storage,
            capacity: num_buffers,
            available
        })
    }

    /// # fn acquire
    /// Function that reserve a 2048 bytes space of a pool to a Buffer.
    ///
    /// # Params
    /// - self: `&Arc<Self>` - Reference to the BufferPool.
    ///
    /// # Returns
    /// - If there is space available for a new Buffer acquisition, returns a new
    /// buffer object, else returns an Err.
    pub fn acquire(self: &Arc<Self>) -> Option<Buffer> {
        self.available.pop().map(|ptr| Buffer {
            ptr,
            capacity: BUFFER_SIZE,
            head: 128,
            size: 0,
            pool: Arc::clone(self)
        })
    }
}
