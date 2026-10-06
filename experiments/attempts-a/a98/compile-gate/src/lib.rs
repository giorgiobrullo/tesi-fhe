//! Compile-only wrapper around the frozen A98 port source.

#[path = "../../src/lib.rs"]
mod frozen_port;

pub use frozen_port::*;
