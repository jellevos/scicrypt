use std::{ptr::null_mut, alloc::Layout};



const ALIGN: usize = 128;

pub struct Scratch {
    layout: Option<Layout>,
    space: *mut u8,
}

impl Scratch {
    pub fn new(size_in_bits: usize) -> Self {
        match size_in_bits {
            0 => Scratch { layout: None, space: null_mut() },
            s => {
                let layout = Layout::from_size_align(s, ALIGN).unwrap();
                unsafe {
                    Scratch { layout: Some(layout), space: std::alloc::alloc(layout) }
                }
            }
        }
    }

    pub fn as_mut(&mut self) -> *mut u64 {
        self.space as *mut u64
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if self.layout.is_some() {
            unsafe {
                std::alloc::dealloc(self.space, self.layout.unwrap());
            }
        }
    }
}
