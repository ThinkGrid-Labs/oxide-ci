use indicatif::{ProgressBar, ProgressStyle};

pub fn info(msg: &str) {
    eprintln!("ℹ️  {}", msg);
}

pub fn success(msg: &str) {
    println!("✅ {}", msg);
}

pub fn warn(msg: &str) {
    eprintln!("⚠️  {}", msg);
}

pub fn create_progress_bar(len: u64) -> ProgressBar {
    let bar = ProgressBar::new(len);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
            .unwrap()
            .progress_chars("##-"),
    );
    bar
}
