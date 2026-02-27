use ignore::{WalkBuilder, Walk};
use std::path::Path;

pub fn get_walker<P: AsRef<Path>>(dir: P) -> Walk {
    // Respects .gitignore rules; hidden(false) ensures dotfiles like .env are included
    WalkBuilder::new(dir).hidden(false).build()
}
