#![warn(clippy::all, rust_2018_idioms)]

mod app;
mod node;

#[cfg(test)]
mod tests;

pub use app::P2PTransfer;
