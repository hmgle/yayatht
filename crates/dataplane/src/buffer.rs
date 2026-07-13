pub const FRAME_CAPACITY: usize = 2048;

pub struct FrameBuffer {
    bytes: Box<[u8; FRAME_CAPACITY]>,
    len: usize,
}

impl Default for FrameBuffer {
    fn default() -> Self {
        Self {
            bytes: Box::new([0; FRAME_CAPACITY]),
            len: 0,
        }
    }
}

impl FrameBuffer {
    #[must_use]
    pub fn writable(&mut self) -> &mut [u8] {
        self.len = 0;
        &mut self.bytes[..]
    }

    pub fn set_len(&mut self, len: usize) {
        assert!(len <= FRAME_CAPACITY);
        self.len = len;
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

pub struct BufferPool {
    buffers: Vec<Option<FrameBuffer>>,
    free: Vec<usize>,
}

impl BufferPool {
    #[must_use]
    pub fn new(count: usize) -> Self {
        Self {
            buffers: (0..count).map(|_| Some(FrameBuffer::default())).collect(),
            free: (0..count).rev().collect(),
        }
    }

    pub fn acquire(&mut self) -> Option<(usize, FrameBuffer)> {
        let index = self.free.pop()?;
        self.buffers[index].take().map(|buffer| (index, buffer))
    }

    pub fn release(&mut self, index: usize, buffer: FrameBuffer) {
        assert!(self.buffers[index].is_none());
        self.buffers[index] = Some(buffer);
        self.free.push(index);
    }

    #[must_use]
    pub fn available(&self) -> usize {
        self.free.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn released_frame_returns_to_fixed_pool() {
        let mut pool = BufferPool::new(1);
        let (index, mut frame) = pool.acquire().unwrap();
        frame.writable()[..3].copy_from_slice(b"tap");
        frame.set_len(3);
        assert_eq!(pool.available(), 0);
        pool.release(index, frame);

        let (_, frame) = pool.acquire().unwrap();
        assert_eq!(frame.bytes(), b"tap");
    }
}
