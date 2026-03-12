/// パスワード入力（`*` マスク表示付き）
use std::io;

/// プロンプトを表示し、入力文字を `*` でマスクしながらパスワードを読み取る。
pub fn password_masked(prompt: &str) -> io::Result<String> {
    #[cfg(unix)]
    {
        unix::password_masked(prompt)
    }
    #[cfg(windows)]
    {
        windows::password_masked(prompt)
    }
}

#[cfg(unix)]
mod unix {
    use std::io::{self, Read as _, Write as _};
    use std::os::unix::io::AsRawFd;

    struct RawModeGuard {
        fd: i32,
        orig: libc::termios,
    }

    impl Drop for RawModeGuard {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.orig);
            }
        }
    }

    pub fn password_masked(prompt: &str) -> io::Result<String> {
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")?;
        let fd = tty.as_raw_fd();

        // Save original termios and enter raw mode
        let orig = unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut t) != 0 {
                return Err(io::Error::last_os_error());
            }
            t
        };
        let guard = RawModeGuard { fd, orig };

        unsafe {
            let mut raw = guard.orig;
            raw.c_lflag &= !(libc::ECHO | libc::ICANON);
            raw.c_cc[libc::VMIN] = 1;
            raw.c_cc[libc::VTIME] = 0;
            if libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        // Write prompt to tty
        {
            let mut w = &tty;
            w.write_all(prompt.as_bytes())?;
            w.flush()?;
        }

        let mut password = String::new();
        let mut reader = io::BufReader::new(&tty);
        let mut buf = [0u8; 1];

        loop {
            if reader.read(&mut buf)? == 0 {
                break;
            }
            match buf[0] {
                b'\n' | b'\r' => {
                    let mut w = &tty;
                    w.write_all(b"\n")?;
                    break;
                }
                // Backspace (0x7F) or BS (0x08)
                0x7F | 0x08 => {
                    if !password.is_empty() {
                        password.pop();
                        let mut w = &tty;
                        w.write_all(b"\x08 \x08")?;
                        w.flush()?;
                    }
                }
                // Ctrl+C
                0x03 => {
                    let mut w = &tty;
                    w.write_all(b"\n")?;
                    w.flush()?;
                    drop(guard);
                    unsafe {
                        libc::raise(libc::SIGINT);
                    }
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted"));
                }
                ch if ch >= 0x20 => {
                    password.push(ch as char);
                    let mut w = &tty;
                    w.write_all(b"*")?;
                    w.flush()?;
                }
                _ => {}
            }
        }

        drop(guard); // restore terminal before returning
        Ok(password)
    }
}

#[cfg(windows)]
mod windows {
    use std::io::{self, Write as _};

    // Windows console API FFI
    extern "system" {
        fn GetStdHandle(nStdHandle: u32) -> *mut core::ffi::c_void;
        fn GetConsoleMode(hConsoleHandle: *mut core::ffi::c_void, lpMode: *mut u32) -> i32;
        fn SetConsoleMode(hConsoleHandle: *mut core::ffi::c_void, dwMode: u32) -> i32;
        fn ReadConsoleA(
            hConsoleInput: *mut core::ffi::c_void,
            lpBuffer: *mut u8,
            nNumberOfCharsToRead: u32,
            lpNumberOfCharsRead: *mut u32,
            pInputControl: *const core::ffi::c_void,
        ) -> i32;
    }

    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // (DWORD)-10
    const ENABLE_PROCESSED_INPUT: u32 = 0x0001;

    struct ConsoleModeGuard {
        handle: *mut core::ffi::c_void,
        orig_mode: u32,
    }

    impl Drop for ConsoleModeGuard {
        fn drop(&mut self) {
            unsafe {
                SetConsoleMode(self.handle, self.orig_mode);
            }
        }
    }

    pub fn password_masked(prompt: &str) -> io::Result<String> {
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };

        let mut orig_mode: u32 = 0;
        if unsafe { GetConsoleMode(handle, &mut orig_mode) } == 0 {
            return Err(io::Error::last_os_error());
        }

        let guard = ConsoleModeGuard { handle, orig_mode };

        // Keep only ENABLE_PROCESSED_INPUT (Ctrl+C works), disable echo & line input
        if unsafe { SetConsoleMode(handle, ENABLE_PROCESSED_INPUT) } == 0 {
            return Err(io::Error::last_os_error());
        }

        eprint!("{}", prompt);
        io::stderr().flush()?;

        let mut password = String::new();
        let mut buf = [0u8; 1];
        let mut read: u32 = 0;

        loop {
            if unsafe { ReadConsoleA(handle, buf.as_mut_ptr(), 1, &mut read, std::ptr::null()) }
                == 0
            {
                return Err(io::Error::last_os_error());
            }
            if read == 0 {
                break;
            }
            match buf[0] {
                b'\r' | b'\n' => {
                    eprintln!();
                    break;
                }
                0x08 => {
                    if !password.is_empty() {
                        password.pop();
                        eprint!("\x08 \x08");
                        io::stderr().flush()?;
                    }
                }
                ch if ch >= 0x20 => {
                    password.push(ch as char);
                    eprint!("*");
                    io::stderr().flush()?;
                }
                _ => {}
            }
        }

        drop(guard);
        Ok(password)
    }
}
