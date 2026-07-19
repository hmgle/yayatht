// SPDX-FileCopyrightText: 2026 hmgle
// SPDX-License-Identifier: GPL-3.0-only

pub struct FrameBuffer {
    bytes: Box<[u8]>,
    len: usize,
}

impl FrameBuffer {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            bytes: vec![0; capacity].into_boxed_slice(),
            len: 0,
        }
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn writable(&mut self) -> &mut [u8] {
        self.len = 0;
        &mut self.bytes[..]
    }

    pub fn set_len(&mut self, len: usize) {
        assert!(len <= self.capacity());
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
    pub fn new(count: usize, frame_capacity: usize) -> Self {
        Self {
            buffers: (0..count)
                .map(|_| Some(FrameBuffer::new(frame_capacity)))
                .collect(),
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
        let mut pool = BufferPool::new(1, 2048);
        let (index, mut frame) = pool.acquire().unwrap();
        assert_eq!(frame.capacity(), 2048);
        frame.writable()[..3].copy_from_slice(b"tap");
        frame.set_len(3);
        assert_eq!(pool.available(), 0);
        pool.release(index, frame);

        let (_, frame) = pool.acquire().unwrap();
        assert_eq!(frame.bytes(), b"tap");
    }
}
