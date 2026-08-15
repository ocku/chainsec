use std::{
    io::{self, Cursor, Read},
    thread,
    time::Duration,
};

use crate::{fetcher::budget::AcquisitionBudget, model::EngineLimits};

struct DelayedReader {
    inner: Cursor<Vec<u8>>,
    delayed: bool,
}

impl Read for DelayedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.delayed {
            self.delayed = true;
            thread::sleep(Duration::from_millis(20));
        }
        self.inner.read(buffer)
    }
}

#[test]
fn tar_extraction_stops_after_a_blocking_read_returns_past_deadline() {
    let mut bytes = Vec::new();
    {
        let mut archive = tar::Builder::new(&mut bytes);
        let contents = b"source";
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_cksum();
        archive
            .append_data(&mut header, "package/index.js", contents.as_slice())
            .unwrap();
        archive.finish().unwrap();
    }
    let destination = tempfile::tempdir().unwrap();
    let deadline = AcquisitionBudget::new(Duration::from_millis(1), u64::MAX).deadline_guard();

    let error = super::super::tar::extract(
        DelayedReader {
            inner: Cursor::new(bytes),
            delayed: false,
        },
        "delayed.tar",
        destination.path(),
        &EngineLimits::default(),
        &deadline,
    )
    .unwrap_err();

    assert_eq!(error.code(), "limit_exceeded", "{error}");
    assert!(error.to_string().contains("package acquisition seconds"));
    assert_eq!(destination.path().read_dir().unwrap().count(), 0);
}
