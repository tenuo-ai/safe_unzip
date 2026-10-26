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
    glob_match::glob_match(pattern, name) || glob_match::glob_match(&fold(pattern), &fold(name))
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
    let stem = upper.split('.').next().unwrap_or(&upper).trim_end();
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
