use ignore::{WalkBuilder, Walk};
use std::path::Path;

pub fn get_parallel_walker<P: AsRef<Path>>(dir: P) -> Walk {
    // using WalkBuilder to ignore things per .gitignore, creating a walker
    WalkBuilder::new(dir).hidden(false).build()
}
