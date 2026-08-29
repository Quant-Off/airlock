use std::path::PathBuf;

use airlock_i18n::tr;
use airlock_setup::{Outcome, SetupOptions};

#[derive(Debug, clap::Args)]
pub struct SetupArgs {
    #[arg(
        long,
        value_name = "FILE",
        help = tr!(
            "생성할 정책 파일 경로. 기본값은 ./airlock.toml",
            "path of the policy file to generate; defaults to ./airlock.toml"
        )
    )]
    pub out: Option<PathBuf>,
}

pub fn exec(args: SetupArgs, global_audit_root: Option<PathBuf>) -> i32 {
    let cwd = match std::env::current_dir() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{}",
                tr!(
                    format!("현재 디렉토리를 확인할 수 없음: {e}"),
                    format!("cannot determine the current directory: {e}")
                )
            );
            return 2;
        }
    };
    let opts = SetupOptions {
        out: args.out,
        cwd,
        home: airlock_policy::path::home_dir(),
        audit_root: global_audit_root.unwrap_or_else(crate::paths::audit_root),
    };
    match airlock_setup::run(&opts) {
        Ok(Outcome::Written(_)) => 0,
        Ok(Outcome::Cancelled) => 1,
        Err(e) => {
            eprintln!("airlock setup: {e}");
            2
        }
    }
}
