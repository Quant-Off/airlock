//! 이 모듈은 신뢰할 수 없는 문자열을 터미널에 안전하게 내보내도록 정제합니다.
//!
//! # Features
//! 경로, argv, 호스트, 규칙 id는 전부 경계 밖에서 온 값입니다. 이스케이프 시퀀스가 그대로
//! 나가면 에이전트가 승인 화면이나 감사 뷰어의 출력을 다시 칠할 수 있습니다. 제어 문자와
//! 양방향 재정렬 문자, 줄 구분 문자를 눈에 보이는 표기로 바꿔 한 값이 한 줄을 넘지 못하게
//! 합니다.
//!
//! # Examples
//! ```rust
//! use airlock_canonical::display::sanitize;
//! assert_eq!(sanitize("ok"), "ok");
//! assert_eq!(sanitize("a\u{1b}[2Kb"), "a\\u{001b}[2Kb");
//! ```

/// 화면을 다시 칠하거나 글자 순서를 뒤집을 수 있는 문자인지 봅니다.
///
/// # Arguments
/// `ch` - 검사할 문자
pub fn is_display_unsafe(ch: char) -> bool {
    ch.is_control()
        || matches!(ch,
            '\u{200E}' | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            // Zl 과 Zp. is_control 이 잡지 못하지만 줄을 나누는 터미널이 있음
            | '\u{2028}' | '\u{2029}')
}

/// 신뢰할 수 없는 문자열을 표시용으로 정제합니다.
///
/// # Arguments
/// `value` - 경계 밖에서 온 문자열
pub fn sanitize(value: &str) -> String {
    if !value.chars().any(is_display_unsafe) {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if is_display_unsafe(ch) {
            out.push_str(&format!("\\u{{{:04x}}}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_untouched() {
        assert_eq!(sanitize("/Users/me/work/a.rs"), "/Users/me/work/a.rs");
        assert_eq!(sanitize("한글 경로/파일.txt"), "한글 경로/파일.txt");
    }

    #[test]
    fn escape_sequences_are_neutralized() {
        let out = sanitize("a\u{1b}[2K\rb");
        assert!(!out.contains('\u{1b}'), "ESC가 남으면 안 됨: {out}");
        assert!(!out.contains('\r'), "CR이 남으면 안 됨: {out}");
    }

    #[test]
    fn newlines_cannot_split_a_line() {
        for raw in ["a\nb", "a\u{2028}b", "a\u{2029}b"] {
            let out = sanitize(raw);
            assert_eq!(out.lines().count(), 1, "{raw:?}가 줄을 나눔: {out}");
        }
    }

    #[test]
    fn bidi_reordering_is_neutralized() {
        for ch in ['\u{202E}', '\u{200F}', '\u{2066}'] {
            let out = sanitize(&format!("a{ch}b"));
            assert!(!out.contains(ch), "{ch:?}가 남으면 안 됨: {out}");
        }
    }
}
