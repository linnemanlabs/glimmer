#!/bin/bash
# using nightly build for -Zlocation-detail=none
# using -Zbuild-std=std,panic_abort to strip paths from binary
RUSTFLAGS="-Zlocation-detail=none" cargo +nightly build --release -Zbuild-std=std,panic_abort --target x86_64-unknown-linux-gnu

objcopy --remove-section=.comment target/x86_64-unknown-linux-gnu/release/beacon
objcopy --remove-section=.note.gnu.build-id target/x86_64-unknown-linux-gnu/release/beacon
objcopy --remove-section=.gnu.build.attributes target/x86_64-unknown-linux-gnu/release/beacon
objcopy --remove-section=.annobin.notes target/x86_64-unknown-linux-gnu/release/beacon

./inspect.sh
