//! We want to support the following configurations:
//!
//! - Configure-time backend selection via RUSTFLAGS="-Ctarget-feature=+avx2".
//! - Runtime backend selection with detection in this crate.
//! - Runtime backend selection with detection handled by the caller.

#[cfg(feature = "autodetect")]
use crate::{Block, Key, Tag};

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    any(target_feature = "avx2", feature = "autodetect"),
))]
pub(crate) mod avx2;

#[cfg(any(
    not(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "avx2"
    )),
    feature = "autodetect",
    fuzzing,
    test,
))]
pub(crate) mod soft;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx2",
    not(feature = "autodetect"),
))]
pub(crate) use avx2::State;

#[cfg(all(
    not(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "avx2",
    )),
    not(feature = "autodetect"),
))]
pub(crate) use soft::State;

#[cfg(feature = "autodetect")]
#[derive(Clone)]
pub(crate) enum State {
    Soft(soft::State),
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Avx2(avx2::State),
}

#[cfg(feature = "autodetect")]
impl State {
    /// Initialize Poly1305State with the given key
    pub(crate) fn new(key: &Key) -> State {
        #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
        {
            use std::is_x86_feature_detected;
            if is_x86_feature_detected!("avx2") {
                return State::Avx2(unsafe { avx2::State::new_unchecked(key) });
            }
        }

        State::Soft(soft::State::new(key))
    }

    /// Reset internal state
    pub(crate) fn reset(&mut self) {
        match self {
            State::Soft(state) => state.reset(),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            State::Avx2(state) => state.reset(),
        }
    }

    /// Compute a Poly1305 block
    pub(crate) fn compute_block(&mut self, block: &Block, partial: bool) {
        match self {
            State::Soft(state) => state.compute_block(block, partial),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            State::Avx2(state) => unsafe { state.compute_block_unchecked(block, partial) },
        }
    }

    pub(crate) fn finalize(&mut self) -> Tag {
        match self {
            State::Soft(state) => state.finalize(),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            State::Avx2(state) => unsafe { state.finalize_unchecked() },
        }
    }
}
