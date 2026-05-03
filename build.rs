fn main() {
    // Run a post-build strip
    println!("cargo:rustc-link-arg=-Wl,--build-id=none");

    // Tell cargo to rerun if build.rs changes
    println!("cargo:rerun-if-changed=build.rs");
}
