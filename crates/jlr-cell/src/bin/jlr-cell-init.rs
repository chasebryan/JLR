//! Helper binary that establishes a cell and executes a sealed program in it.
//! It is started by `jlr_cell::launch`; it is not meant to be run by hand.

#![forbid(unsafe_code)]

fn main() {
    std::process::exit(jlr_cell::cell_main());
}
