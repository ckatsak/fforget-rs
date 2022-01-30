#![deny(missing_docs)]

//! This crate provides an opinionated, high-level interface for some Linux page cache inspection
//! and manipulation system calls.

use std::{
    fs, io, num,
    os::unix::prelude::IntoRawFd,
    path::{Path, PathBuf},
    ptr,
};

use bitvec::vec::BitVec;

/// An error type returned by calls to the API exposed by this crate.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Failed to retrieve configured page size using `libc::sysconf(libc::_SC_PAGESIZE)`.
    #[error("Failed to retrieve page size")]
    PageSizeError(#[source] io::Error),

    /// Forwarded [`std::io::Error`], returned from the attempt to `open(2)` a file (using
    /// [`std::fs::OpenOptions`]).
    #[error("Failed to open(2) file {0:?}")]
    OpenError(PathBuf, #[source] io::Error),

    /// Forwarded [`std::io::Error`], returned from the attempt to `stat(2)` a file (using
    /// [`std::fs::File::metadata`]).
    #[error("Failed to stat(2) file {0:?}")]
    StatError(PathBuf, #[source] io::Error),

    /// Forwarded [`std::num::TryFromIntError`], returned from the attempt to convert the `u64`
    /// file length (returned by [`std::fs::File::metadata`]) into a `i64` (as required by
    /// `libc::posix_fadvise64`).
    #[error("Failed to convert file length from u64 to i64")]
    TryFromIntError(#[from] num::TryFromIntError),

    /// A [`std::io::Error`] built from the error code returned by `libc::posix_fadvise64`.
    #[error("posix_fadvise64(2) failed")]
    PosixFadvise64Error(#[source] io::Error),

    /// A [`std::io::Error`] built from the errno set by `libc::mmap`.
    #[error("mmap(2) failed")]
    MmapError(#[source] io::Error),

    /// A [`std::io::Error`] built from the errno set by `libc::munmap`.
    #[error("munmap(2) failed")]
    MunmapError(#[source] io::Error),

    /// A [`std::io::Error`] built from the errno set by `libc::mincore`.
    #[error("mincore(2) failed")]
    MincoreError(#[source] io::Error),
}

/// Hint Linux to remove the file at `path` from the page cache.
pub fn fforget(path: impl AsRef<Path>) -> Result<(), Error> {
    let f = fs::OpenOptions::new()
        .read(true)
        .open(&path)
        .map_err(|err| Error::OpenError(path.as_ref().to_path_buf(), err))?;
    let len = f
        .metadata()
        .map_err(|err| Error::StatError(path.as_ref().to_path_buf(), err))?
        .len()
        .try_into()?;

    // SAFETY: call to libc with safe parameters
    match unsafe { libc::posix_fadvise64(f.into_raw_fd(), 0, len, libc::POSIX_FADV_DONTNEED) } {
        0 => Ok(()),
        er => Err(Error::PosixFadvise64Error(io::Error::from_raw_os_error(er))),
    }
}

/// Stored results of a `mincore(2)` call for a specific file.
pub struct Mincore {
    page_size: usize,
    /// A condensed representation of `mincore(2)`'s `vec` out-argument.
    vec: BitVec,
}

impl TryFrom<Vec<u8>> for Mincore {
    type Error = Error;

    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self {
            page_size: page_size()?,
            vec: BitVec::from_iter(vec.iter().map(|&b| b & 1 == 1)),
        })
    }
}

impl Mincore {
    /// Returns the configured page size at the time `mincore(2)` was called.
    #[inline]
    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// Returns the number of (page-sized) blocks that this [`Mincore`] captured (i.e., at the time
    /// `mincore(2)` was called).
    #[allow(clippy::len_without_is_empty)]
    #[inline]
    pub fn len(&self) -> usize {
        self.vec.len()
    }

    /// Returns the number of page-sized blocks that resided in the page cache at the time
    /// `mincore(2)` was called.
    #[inline]
    pub fn cached_pages(&self) -> usize {
        self.vec.count_ones()
    }

    /// Given a block index for the file that this [`Mincore`] refers to (and assuming page-sized
    /// blocks), it returns `true` if the block appeared to reside in the page cache at the time
    /// `mincore(2)` was called, or `false` otherwise.
    ///
    /// # Panics
    ///
    /// This method panics if the provided block index is out of bounds; i.e., if the file
    /// consisted of fewer (page-sized) blocks than what the provided index implies, at the time
    /// `mincore(2)` was called.
    /// It is the responsibility of the caller to provide a valid block index.
    #[inline]
    pub fn block_present(&self, block_index: usize) -> bool {
        self.vec[block_index]
    }

    /// Given an offset in the file that this [`Mincore`] refers to, it returns `true` if the
    /// offset appeared to reside in the page cache at the time `mincore(2)` was called, or `false`
    /// otherwise.
    ///
    /// # Panics
    ///
    /// This method panics if the provided offset is out of bounds; i.e., if the file consisted of
    /// fewer page-sized blocks than what the provided offset implies, at the time `mincore(2)` was
    /// called.
    /// It is the responsibility of the caller to provide a valid offset.
    #[inline]
    pub fn offset_present(&self, offset_index: usize) -> bool {
        self.vec[offset_index / self.page_size]
    }
}

/// Returns true if any part of the given file currently resides in the page cache.
#[inline]
pub fn fcached(path: impl AsRef<Path>) -> Result<bool, Error> {
    Ok(mincore_raw(path)?.iter().any(|b| b & 1 == 1))
}

/// A safe, opinionated, high-level interface for the `mincore(2)` Linux system call.
#[inline]
pub fn mincore(path: impl AsRef<Path>) -> Result<Mincore, Error> {
    mincore_raw(path)?.try_into()
}

/// Returns a `Vec<u8>`, filled up by the `mincore(2)` system call after `mmap(2)`ing the file at
/// the provided `path`.
pub fn mincore_raw(path: impl AsRef<Path>) -> Result<Vec<u8>, Error> {
    let f = fs::OpenOptions::new()
        .read(true)
        .open(&path)
        .map_err(|err| Error::OpenError(path.as_ref().to_path_buf(), err))?;
    let len = f
        .metadata()
        .map_err(|err| Error::StatError(path.as_ref().to_path_buf(), err))?
        .len()
        .try_into()?;

    // SAFETY: call to libc with checked parameters
    let f_map = unsafe {
        libc::mmap(
            ptr::null_mut(),
            len,
            libc::PROT_NONE,
            libc::MAP_SHARED,
            f.into_raw_fd(),
            0,
        )
    };
    if f_map == libc::MAP_FAILED {
        return Err(Error::MmapError(io::Error::last_os_error()));
    }

    let page_size = page_size()?;
    let mut vec = vec![0; (len + page_size - 1) / page_size];

    // SAFETY: call to libc with checked parameters
    if -1 == unsafe { libc::mincore(f_map, len, vec.as_mut_ptr()) } {
        return Err(Error::MincoreError(io::Error::last_os_error()));
    }

    // SAFETY: call to libc with checked parameters
    if -1 == unsafe { libc::munmap(f_map, len) } {
        return Err(Error::MunmapError(io::Error::last_os_error()));
    }

    Ok(vec)
}

/// Retrieve system's page size in bytes.
pub fn page_size() -> Result<usize, Error> {
    // SAFETY: call to libc with safe parameters
    match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
        -1 => Err(Error::PageSizeError(io::Error::last_os_error())),
        size => Ok(size as usize),
    }
}

// TEMPORARY _UNRELIABLE_ TESTS
//
//#[cfg(test)]
//mod tests {
//    use super::*;
//    use anyhow::Result;
//    use std::fs;
//
//    const FILE_PATH: &str = "src/lib.rs";
//
//    #[test]
//    fn fcached_this() -> Result<()> {
//        let _ = fs::read_to_string(FILE_PATH)?;
//        assert!(fcached("src/lib.rs")?);
//
//        fforget(FILE_PATH)?;
//        assert!(!fcached("src/lib.rs")?);
//
//        Ok(())
//    }
//
//    #[test]
//    fn bitvec() -> Result<()> {
//        let m = mincore(FILE_PATH)?;
//
//        let _ = fs::read_to_string(FILE_PATH)?;
//        if fcached("src/lib.rs")? {
//            assert!(m.offset_present(0));
//            assert_eq!(m.offset_present(0), m.block_present(0));
//        }
//
//        Ok(())
//    }
//}
