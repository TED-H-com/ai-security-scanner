//! Fixed cancellation channel from the bootstrap; never a command interpreter.

use std::io;

pub(super) fn listen(on_stop: impl FnOnce(u8) + Send + 'static) -> io::Result<()> {
    std::thread::Builder::new()
        .name("bootstrap-parent-control".into())
        .spawn(move || on_stop(read_cancellation(io::stdin().lock())))?;
    // The listener owns only stdin. Normal process exit can leave it waiting
    // after the execution owner has joined and committed its receipt. Parent
    // death closes the pipe; Windows needs no forceful child.kill().
    Ok(())
}

fn read_cancellation(mut input: impl io::Read) -> u8 {
    let mut line = Vec::with_capacity(16);
    loop {
        let mut byte = [0];
        match input.read(&mut byte) {
            Ok(0) => return 130,
            Ok(_) => {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    return match line.as_slice() {
                        b"cancel\n" => 130,
                        b"terminate\n" => 143,
                        _ => 4,
                    };
                }
                if line.len() >= 16 {
                    return 4;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_control_is_bounded_and_never_interprets_commands() {
        assert_eq!(read_cancellation(&b"cancel\n"[..]), 130);
        assert_eq!(read_cancellation(&b"terminate\n"[..]), 143);
        assert_eq!(read_cancellation(&b""[..]), 130);
        assert_eq!(read_cancellation(&b"cancel"[..]), 130);
        assert_eq!(read_cancellation(&b"execute shell\n"[..]), 4);
        assert_eq!(read_cancellation(&b"x".repeat(17)[..]), 4);
    }
}
