use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("build_info.rs");
    let mut f = File::create(&dest_path).unwrap();

    let code = format!(
        "
    pub fn get_commit_id() -> &'static str {{
           {:?}
    }}
   ",
        format!(
            "{} {}",
            get_commit_describe().unwrap_or_default(),
            get_commit_date().unwrap_or_default()
        )
    );

    f.write_all(code.as_bytes()).unwrap();
}

pub fn get_commit_describe() -> Option<String> {
    std::process::Command::new("git")
        .args(&["describe", "--dirty", "--tags"])
        .output()
        .ok()
        .and_then(|r| {
            String::from_utf8(r.stdout).ok().map(|s| {
                s.trim()
                    .splitn(2, "-")
                    .collect::<Vec<&str>>()
                    .pop()
                    .unwrap_or_default()
                    .to_string()
            })
        })
}

pub fn get_commit_date() -> Option<String> {
    std::process::Command::new("git")
        .env("TZ", "UTC")
        .args(&["log", "-1", "--date=short-local", "--pretty=format:%cd"])
        .output()
        .ok()
        .and_then(|r| {
            String::from_utf8(r.stdout)
                .ok()
                .map(|s| s.trim().to_string())
        })
}
