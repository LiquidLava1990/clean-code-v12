//! Atomic-write fault tests for [`cc_baseline::io::atomic_write_with`].

use std::io::{self, Write};

use camino::Utf8PathBuf;
use cc_baseline::io::{atomic_write, atomic_write_with};
use tempfile::tempdir;

fn tmp_path(dir: &tempfile::TempDir, name: &str) -> Utf8PathBuf {
    Utf8PathBuf::from_path_buf(dir.path().join(name)).expect("utf8 tempdir")
}

/// `Write` impl that fails after `fail_after` bytes — simulates a
/// kill-9 / disk-full mid-write.
struct FailingWriter {
    written: usize,
    fail_after: usize,
}

impl Write for FailingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written >= self.fail_after {
            return Err(io::Error::other("simulated mid-write failure"));
        }
        let take = buf.len().min(self.fail_after - self.written);
        self.written += take;
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn atomic_save_no_partial_write() {
    let dir = tempdir().expect("tempdir");
    let path = tmp_path(&dir, "baseline.json");

    // Step 1: lay down a known-good baseline file.
    let original = br#"{"sentinel":"original"}"#;
    atomic_write(&path, original).expect("initial write");
    assert_eq!(std::fs::read(&path).unwrap(), original);

    // Step 2: attempt a fault-injecting write that fails partway.
    let result = atomic_write_with(&path, |sink| {
        // Write 8 bytes through a sink that explodes after 4.
        let mut failing = FailingWriter {
            written: 0,
            fail_after: 4,
        };
        // Pump bytes through the sink AND the failing writer; once
        // failing returns Err, the body returns Err and atomic_write
        // must NOT promote the temp file.
        sink.write_all(b"abcd").ok();
        failing.write_all(b"abcdefgh")?; // <- fails on 5th byte
        sink.write_all(b"efgh")?;
        Ok(())
    });
    assert!(result.is_err(), "fault-injected write must fail");

    // Step 3: original file is intact (rename never happened).
    assert_eq!(
        std::fs::read(&path).unwrap(),
        original,
        "original file must survive a failed atomic write"
    );
}
