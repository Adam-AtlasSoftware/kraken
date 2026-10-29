// A freestanding Rust program for the demangler tests: its functions carry Rust symbol names
// (legacy `_ZN...17h<hash>E` or v0 `_R...`, chosen by `-C symbol-mangling-version`), and
// there is no std, so the binary is small.
#![no_std]
#![no_main]

unsafe extern "C" {
    fn puts(s: *const u8) -> i32;
}

pub mod greeter {
    pub struct Greeting<T>(pub T);

    impl<T: Copy + Into<u32>> Greeting<T> {
        #[inline(never)]
        pub fn weight(&self) -> u32 {
            let v: u32 = self.0.into();
            v.wrapping_mul(31).wrapping_add(7)
        }
    }

    #[inline(never)]
    pub fn say(msg: &'static [u8]) -> i32 {
        unsafe { super::puts(msg.as_ptr()) }
    }
}

#[inline(never)]
fn checksum(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |acc, b| acc.rotate_left(5) ^ u32::from(*b))
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, _argv: *const *const u8) -> i32 {
    let w = greeter::Greeting(argc as u8).weight() + greeter::Greeting(argc as u16 + 300).weight();
    let c = checksum(&[argc as u8, 1, 2, 3]);
    greeter::say(b"hello from rust\0");
    (w ^ c) as i32 & 0x7f
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
