//! Filename rules that hold across filesystems.
//!
//! Extraction may target case-insensitive or Unicode-normalizing filesystems
//! (macOS, Windows) and Windows, which drops trailing dots and spaces from
//! names. These helpers treat names that refer to the same file there as
//! equivalent, and reject names whose meaning changes between platforms.

use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;

/// Case-folded, NFC-normalized form of `s`, for comparing names the way
/// case-insensitive, normalization-insensitive filesystems do.
pub(crate) fn fold(s: &str) -> String {
    s.nfd().case_fold().nfc().collect()
}

/// Whether glob `pattern` matches `name`, either exactly or after folding
/// both. Used for exclusions, so an entry can't avoid an exclude pattern by
/// differing only in case or Unicode normalization.
pub(crate) fn glob_matches_folded(pattern: &str, name: &str) -> bool {
    glob_match::glob_match(pattern, name)
        || glob_match::glob_match(&fold_glob_literals(pattern), &fold_for_glob(name))
}

/// Fold literal portions of a glob while leaving character classes intact.
///
/// Normalizing an entire glob changes its syntax: for example, folding
/// `[A-z]` into `[a-z]` removes punctuation from the range. Using NFD here
/// also lets a wildcard consume combining marks at a normalization boundary,
/// so `cafe*.txt` matches both composed and decomposed forms of `café.txt`.
fn fold_glob_literals(pattern: &str) -> String {
    let bytes = pattern.as_bytes();
    let mut out = String::with_capacity(pattern.len());
    let mut literal_start = 0;
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i = (i + 2).min(bytes.len());
            continue;
        }
        if bytes[i] == b'[' {
            if let Some(end) = character_class_end(bytes, i + 1) {
                out.push_str(&fold_for_glob(&pattern[literal_start..i]));
                out.push_str(&pattern[i..=end]);
                i = end + 1;
                literal_start = i;
                continue;
            }
        }
        i += 1;
    }

    out.push_str(&fold_for_glob(&pattern[literal_start..]));
    out
}

fn fold_for_glob(s: &str) -> String {
    s.nfd().case_fold().collect()
}

fn character_class_end(bytes: &[u8], mut i: usize) -> Option<usize> {
    if i < bytes.len() && matches!(bytes[i], b'^' | b'!') {
        i += 1;
    }

    let mut first = true;
    let mut escaped = false;
    while i < bytes.len() {
        if escaped {
            escaped = false;
            first = false;
        } else if bytes[i] == b'\\' {
            escaped = true;
        } else if bytes[i] == b']' && !first {
            return Some(i);
        } else {
            first = false;
        }
        i += 1;
    }
    None
}

/// Why a single path component can't be extracted portably, if it can't.
pub(crate) fn component_issue(component: &str) -> Option<&'static str> {
    // Windows strips trailing dots and spaces, so "a.txt." and "CON " would
    // be written as "a.txt" and "CON".
    if component.ends_with('.') || component.ends_with(' ') {
        return Some("component ends with a dot or space");
    }

    // On Windows, ':' selects an NTFS alternate data stream or a drive.
    if cfg!(windows) && component.contains(':') {
        return Some("contains ':'");
    }

    let upper = component.to_ascii_uppercase();
    let stem = upper
        .split('.')
        .next()
        .unwrap_or(&upper)
        .trim_end_matches(' ');
    match stem {
        "CON" | "PRN" | "AUX" | "NUL" | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6"
        | "COM7" | "COM8" | "COM9" | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6"
        | "LPT7" | "LPT8" | "LPT9" => Some("Windows reserved name"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folding() {
        assert_eq!(fold("ReadMe.TXT"), fold("readme.txt"));
        assert_eq!(fold("caf\u{e9}"), fold("cafe\u{301}"));
        assert_ne!(fold("a.txt"), fold("b.txt"));
    }

    #[test]
    fn folded_glob_matching() {
        assert!(glob_matches_folded("**/.git/**", "x/.git/config"));
        assert!(glob_matches_folded("**/.git/**", "x/.GIT/config"));
        assert!(glob_matches_folded("**/*.exe", "bin/Tool.EXE"));
        assert!(glob_matches_folded("**/caf\u{e9}/**", "cafe\u{301}/a"));
        assert!(glob_matches_folded("cafe*.txt", "caf\u{e9}.TXT"));
        assert!(glob_matches_folded("[A-z].txt", "_.TXT"));
        assert!(!glob_matches_folded("**/.git/**", "x/git/config"));
    }

    #[test]
    fn component_rules() {
        assert_eq!(component_issue("a.txt"), None);
        assert_eq!(component_issue(".hidden"), None);
        assert!(component_issue("a.txt.").is_some());
        assert!(component_issue("a.txt ").is_some());
        assert!(component_issue("dir.").is_some());
        assert!(component_issue("CON").is_some());
        assert!(component_issue("con.txt").is_some());
        assert!(component_issue("LPT1").is_some());
        assert_eq!(component_issue("console.txt"), None);
        assert_eq!(component_issue("CON\u{a0}.txt"), None);
        assert_eq!(
            component_issue("a:b"),
            if cfg!(windows) {
                Some("contains ':'")
            } else {
                None
            }
        );
    }
}
