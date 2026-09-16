use std::path::{Path, PathBuf};

use airlock_canonical::display::sanitize;
use airlock_i18n::tr;
use airlock_policy::Policy;
use airlock_setup::{Outcome, SetupOptions};

use crate::{paths, trust};

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
    let audit_root = paths::absolutize(&global_audit_root.unwrap_or_else(paths::audit_root), &cwd);
    let opts = SetupOptions {
        out: args.out,
        cwd,
        home: airlock_policy::path::home_dir(),
        audit_root,
    };
    match airlock_setup::run(&opts) {
        Ok(Outcome::Written(out)) => {
            // 사용자가 방금 생성에 동의한 파일이므로 첫 실행에서 다시 묻지 않게 기록합니다.
            // 기록 실패는 마법사의 결과를 뒤집을 일이 아니라 첫 실행에서 확인을 받게 될 뿐입니다
            record_written(&out, &opts);
            0
        }
        Ok(Outcome::Cancelled) => 1,
        Err(e) => {
            eprintln!("airlock setup: {e}");
            2
        }
    }
}

fn record_written(out: &Path, opts: &SetupOptions) {
    let path = paths::absolutize_lexical(out, &opts.cwd);
    let shown = sanitize(&path.display().to_string());
    let ctx = paths::load_context(opts.home.clone(), &opts.audit_root, &opts.cwd, Some(&path));
    let result = Policy::load_file(&path, &ctx)
        .map_err(|e| e.to_string())
        .and_then(|policy| trust::record_approval(&path, &policy, &opts.audit_root));
    match result {
        Ok((rec, _)) => eprintln!(
            "airlock setup: {}",
            tr!(
                format!(
                    "정책 신뢰 기록에 추가함 (다이제스트 {})",
                    rec.digest.chars().take(12).collect::<String>()
                ),
                format!(
                    "added to the policy trust record (digest {})",
                    rec.digest.chars().take(12).collect::<String>()
                )
            )
        ),
        Err(why) => {
            eprintln!(
                "airlock setup: {}",
                tr!(
                    format!("경고 정책 신뢰 기록에 추가하지 못함: {why}"),
                    format!("warning: could not add to the policy trust record: {why}")
                )
            );
            eprintln!(
                "airlock setup: {}",
                tr!(
                    format!(
                        "첫 airlock run 에서 확인을 받거나 airlock policy trust {shown} 로 승인할 것"
                    ),
                    format!(
                        "confirm on the first airlock run or approve with airlock policy trust {shown}"
                    )
                )
            );
        }
    }
}
