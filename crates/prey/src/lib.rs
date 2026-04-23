use std::alloc::{alloc, Layout};
use std::sync::Arc;
use crossbeam_queue::ArrayQueue;
const CACHE_LINE: usize = 64;
const BUFFER_SIZE: usize = 2048;
pub struct Buffer {
    ptr: *mut u8,
    capacity: usize,
    head: usize,
    size: usize,
    pool: Arc<BufferPool>
}

impl Buffer {
    pub fn as_mut_slice(&mut self) ->&mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(
                self.ptr.add(self.head),
                self.capacity - self.head
            )
        }
    }

}
impl Drop for Buffer {
    fn drop(&mut self) {
        let _ = self.pool.available.push(self.ptr);
    }
}
pub struct BufferPool {
    storage: *mut u8,
    capacity: usize,
    available: ArrayQueue<*mut u8>
}

impl BufferPool {
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
