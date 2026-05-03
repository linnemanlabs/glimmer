//! Runtime support for compile-time obfuscated strings
pub use glimmer_obfstr_macros::obfs;

#[cfg(test)]
extern crate self as glimmer_obfstr;

/// Stack-allocated buffer zero'd on drop
/// const generic 'N' produces uniquely-sized type to prevent
/// becoming a type-based signature across the binary.
pub struct SecureBuffer<const N: usize> {
    buf: [u8; N],
}

impl<const N: usize> SecureBuffer<N> {
    /// Called by generated code from obfs!()
    #[inline(always)]
    pub fn new(buf: [u8; N]) -> Self {
        Self { buf }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Interpret the decoded bytes as UTF-8
    ///
    /// panics on invalid UTF-8, input was &str literal, UTF-8 is "guaranteed"
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf).expect("")
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        N
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> Drop for SecureBuffer<N> {
    fn drop(&mut self) {
        for byte in self.buf.iter_mut() {
            // we are writing to our own stack allocation through
            // a valid mutable reference. The volatile qualifier prevents
            // dead-store elimination
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }

        // ensure the volatile writes are not reordered
        // past this point by the CPU or compiler
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Allow obfs!("...").as_bytes() and &*obfs!("...") to get &[u8]
impl<const N: usize> core::ops::Deref for SecureBuffer<N> {
    type Target = [u8];

    #[inline(always)]
    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

/// Allow passing directly to functions expecting AsRef<[u8]>
impl<const N: usize> AsRef<[u8]> for SecureBuffer<N> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

/// Display the decoded string content
/// creates a temporary &str on the stack for formatting.
/// the &str points into our buffer which will be zeroed on drop
impl<const N: usize> core::fmt::Display for SecureBuffer<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Debug representation shows "" rather than the contents.
/// Prevents accidental leakage via `dbg!()` or `{:?}` formatting
/// into logs. An analyst looking at debug output sees nothing useful.
impl<const N: usize> core::fmt::Debug for SecureBuffer<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let decoded = obfs!("hello world");
        assert_eq!(decoded.as_str(), "hello world");
        assert_eq!(decoded.len(), 11);
    }

    #[test]
    fn test_empty_string() {
        let decoded = obfs!("");
        assert_eq!(decoded.as_str(), "");
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_special_chars() {
        let decoded = obfs!("POST / HTTP/1.1\r\n");
        assert_eq!(decoded.as_str(), "POST / HTTP/1.1\r\n");
    }

    #[test]
    fn test_long_string() {
        // should hit the loop path (>96 bytes)
        let decoded = obfs!(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        );
        assert_eq!(decoded.as_str(), "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36");
    }

    #[test]
    fn test_debug_redacted() {
        let decoded = obfs!("secret");
        assert_eq!(format!("{:?}", decoded), "");
    }

    #[test]
    fn test_as_bytes() {
        let decoded = obfs!("/proc/self/mountinfo");
        assert_eq!(decoded.as_bytes(), b"/proc/self/mountinfo");
    }
}