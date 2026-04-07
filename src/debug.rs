#[cfg(feature = "debug")]
#[macro_export]
macro_rules! dbg_log {
    ($($arg:tt)*) => {
        eprintln!("[debug] {}", format!($($arg)*));
    };
}

#[cfg(not(feature = "debug"))]
#[macro_export]
macro_rules! dbg_log {
    ($($arg:tt)*) => {};
}