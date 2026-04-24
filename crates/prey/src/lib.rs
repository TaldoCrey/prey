//! # Prey
//! _Packet Routing Engine Yield_
//!
//! This is the core of the whole framework
//! By now, contains buffer management and recycling.
//! > **Its still under development**
//!
//! ## Buffer Management
//! The way PREY deals with buffers is simple but smart:
//! It allocates space once, and all the remaining management is done by
//! itself. This makes PREY really efficient in terms of speed while dealing
//! with memory, since it does not need to depend on kernel and OS services during
//! its runtime, only at its start.
//!
//! It uses an efficient memory layout to prevent unnecessary space allocation,
//! using cache lines fixed on 64 bits per line.
//!
//! Buffers have a fixed size of 2048 bytes, but they aren't fully filled with
//! information. Since normal Network packets does not exceed 1500 bytes of length
//! PREY buffers will be able to contain all packets' info and still be able to
//! add new data to it, without the need to expand the buffer size.

pub mod buffer;