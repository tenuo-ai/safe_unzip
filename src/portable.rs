//! Filename rules that hold across filesystems.
//!
//! Extraction may target case-insensitive or Unicode-normalizing filesystems
//! (macOS, Windows) and Windows, which drops trailing dots and spaces from
//! names. These helpers treat names that refer to the same file there as
//! equivalent, and reject names whose meaning changes between platforms.

use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::char::canonical_combining_class;
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
    let negations = pattern.chars().take_while(|ch| *ch == '!').count();
    let positive = &pattern[negations..];
    let matched = glob_match::glob_match(positive, name) || equivalent_glob_match(positive, name);
    if negations % 2 == 1 {
        !matched
    } else {
        matched
    }
}

fn fold_for_glob(s: &str) -> String {
    s.nfd().case_fold().collect()
}

#[derive(Debug)]
enum GlobToken {
    Literal(String),
    Separator,
    Any,
    Star,
    GlobStar,
    GlobStarDirectory,
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
}

#[derive(Debug)]
struct NameUnit {
    text: String,
    folded: String,
    separator: bool,
}

/// Match a glob against any case- or normalization-equivalent spelling of a
/// name. This is deliberately token-aware: folding raw glob text can change a
/// range (`[A-f]`), turn a literal hyphen into a range, or split one Unicode
/// class member into several code points.
fn equivalent_glob_match(pattern: &str, name: &str) -> bool {
    let Some(patterns) = expand_braces(pattern) else {
        return false;
    };
    let units = name_units(name);
    patterns.into_iter().any(|pattern| {
        let Some(tokens) = tokenize_glob(&pattern) else {
            return false;
        };
        match_tokens(&tokens, &units)
    })
}

fn expand_braces(pattern: &str) -> Option<Vec<String>> {
    fn recurse(pattern: String, depth: usize, output: &mut Vec<String>) -> Option<()> {
        if depth > 10 || output.len() >= 256 {
            return None;
        }
        let chars: Vec<char> = pattern.chars().collect();
        let mut escaped = false;
        let mut in_class = false;
        let mut open = None;
        for (i, ch) in chars.iter().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '[' => in_class = true,
                ']' => in_class = false,
                '{' if !in_class => {
                    open = Some(i);
                    break;
                }
                _ => {}
            }
        }
        let Some(open) = open else {
            output.push(pattern);
            return Some(());
        };

        let mut level = 1;
        let mut escaped = false;
        let mut in_class = false;
        let mut commas = Vec::new();
        let mut close = None;
        for (i, ch) in chars.iter().copied().enumerate().skip(open + 1) {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '[' => in_class = true,
                ']' => in_class = false,
                '{' if !in_class => level += 1,
                '}' if !in_class => {
                    level -= 1;
                    if level == 0 {
                        close = Some(i);
                        break;
                    }
                }
                ',' if !in_class && level == 1 => commas.push(i),
                _ => {}
            }
        }
        let close = close?;
        commas.push(close);

        let prefix: String = chars[..open].iter().collect();
        let suffix: String = chars[close + 1..].iter().collect();
        let mut option_start = open + 1;
        for option_end in commas {
            let option: String = chars[option_start..option_end].iter().collect();
            recurse(format!("{prefix}{option}{suffix}"), depth + 1, output)?;
            option_start = option_end + 1;
        }
        Some(())
    }

    let mut output = Vec::new();
    recurse(pattern.to_owned(), 0, &mut output)?;
    Some(output)
}

fn tokenize_glob(pattern: &str) -> Option<Vec<GlobToken>> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut tokens = Vec::new();
    let mut literal = String::new();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '\\' => {
                i += 1;
                literal.push(*chars.get(i)?);
                i += 1;
            }
            '/' => {
                push_literal(&mut tokens, &mut literal);
                tokens.push(GlobToken::Separator);
                i += 1;
            }
            '?' => {
                push_literal(&mut tokens, &mut literal);
                tokens.push(GlobToken::Any);
                i += 1;
            }
            '*' => {
                push_literal(&mut tokens, &mut literal);
                let start = i;
                while i < chars.len() && chars[i] == '*' {
                    i += 1;
                }
                let is_component = i - start >= 2
                    && (start == 0 || chars[start - 1] == '/')
                    && (i == chars.len() || chars[i] == '/');
                if is_component && i < chars.len() {
                    // Consume the following slash. The whole `**/` segment is
                    // optional, as in the upstream glob matcher.
                    tokens.push(GlobToken::GlobStarDirectory);
                    i += 1;
                } else if is_component {
                    tokens.push(GlobToken::GlobStar);
                } else {
                    tokens.push(GlobToken::Star);
                }
            }
            '[' => {
                push_literal(&mut tokens, &mut literal);
                let (token, next) = parse_class(&chars, i)?;
                tokens.push(token);
                i = next;
            }
            c => {
                literal.push(c);
                i += 1;
            }
        }
    }
    push_literal(&mut tokens, &mut literal);
    Some(tokens)
}

fn push_literal(tokens: &mut Vec<GlobToken>, literal: &mut String) {
    if !literal.is_empty() {
        tokens.push(GlobToken::Literal(fold_for_glob(literal)));
        literal.clear();
    }
}

fn parse_class(chars: &[char], start: usize) -> Option<(GlobToken, usize)> {
    let mut i = start + 1;
    let negated = matches!(chars.get(i), Some('!') | Some('^'));
    if negated {
        i += 1;
    }

    let mut members = Vec::new();
    let mut first = true;
    while i < chars.len() && (first || chars[i] != ']') {
        let (low, next) = class_char(chars, i)?;
        i = next;
        let high = if i + 1 < chars.len() && chars[i] == '-' && chars[i + 1] != ']' {
            let (high, next) = class_char(chars, i + 1)?;
            i = next;
            high
        } else {
            low
        };
        members.push((low, high));
        first = false;
    }
    if i >= chars.len() || members.is_empty() {
        return None;
    }
    Some((
        GlobToken::Class {
            negated,
            ranges: members,
        },
        i + 1,
    ))
}

fn class_char(chars: &[char], i: usize) -> Option<(char, usize)> {
    if chars.get(i) == Some(&'\\') {
        Some((*chars.get(i + 1)?, i + 2))
    } else {
        Some((*chars.get(i)?, i + 1))
    }
}

fn name_units(name: &str) -> Vec<NameUnit> {
    name.nfd()
        .map(|ch| {
            let text = ch.to_string();
            NameUnit {
                folded: fold_for_glob(&text),
                separator: text == "/",
                text,
            }
        })
        .collect()
}

fn match_tokens(tokens: &[GlobToken], units: &[NameUnit]) -> bool {
    let mut next = vec![false; units.len() + 1];
    next[units.len()] = true;

    for token in tokens.iter().rev() {
        let mut current = vec![false; units.len() + 1];
        match token {
            GlobToken::Literal(expected) => {
                for unit_index in (0..units.len()).rev() {
                    current[unit_index] =
                        consume_literal(expected, units, unit_index).is_some_and(|end| next[end]);
                }
            }
            GlobToken::Separator => {
                for unit_index in (0..units.len()).rev() {
                    current[unit_index] = units[unit_index].separator && next[unit_index + 1];
                }
            }
            GlobToken::Any => {
                for unit_index in (0..units.len()).rev() {
                    current[unit_index] =
                        !units[unit_index].separator && next[next_cluster(units, unit_index)];
                }
            }
            GlobToken::Class { negated, ranges } => {
                for unit_index in (0..units.len()).rev() {
                    current[unit_index] = class_match_end(*negated, ranges, units, unit_index)
                        .is_some_and(|end| next[end]);
                }
            }
            GlobToken::Star => {
                current[units.len()] = next[units.len()];
                for unit_index in (0..units.len()).rev() {
                    current[unit_index] =
                        next[unit_index] || !units[unit_index].separator && current[unit_index + 1];
                }
            }
            GlobToken::GlobStar => {
                current[units.len()] = next[units.len()];
                for unit_index in (0..units.len()).rev() {
                    current[unit_index] = next[unit_index] || current[unit_index + 1];
                }
            }
            GlobToken::GlobStarDirectory => {
                let mut later_separator_matches = false;
                current[units.len()] = next[units.len()];
                for unit_index in (0..units.len()).rev() {
                    if units[unit_index].separator && next[unit_index + 1] {
                        later_separator_matches = true;
                    }
                    current[unit_index] = next[unit_index] || later_separator_matches;
                }
            }
        }
        next = current;
    }
    next[0]
}

fn consume_literal(expected: &str, units: &[NameUnit], start: usize) -> Option<usize> {
    let mut actual = String::new();
    for (offset, unit) in units[start..].iter().enumerate() {
        if unit.separator {
            return None;
        }
        actual.push_str(&unit.folded);
        if actual == expected {
            return Some(start + offset + 1);
        }
        if !expected.starts_with(&actual) {
            return None;
        }
    }
    None
}

fn next_cluster(units: &[NameUnit], start: usize) -> usize {
    let mut end = start + 1;
    while end < units.len()
        && !units[end].separator
        && units[end]
            .text
            .chars()
            .next()
            .is_some_and(|ch| canonical_combining_class(ch) != 0)
    {
        end += 1;
    }
    end
}

fn class_match_end(
    negated: bool,
    ranges: &[(char, char)],
    units: &[NameUnit],
    start: usize,
) -> Option<usize> {
    if units.get(start)?.separator {
        return None;
    }
    let end = next_cluster(units, start);
    let text: String = units[start..end]
        .iter()
        .map(|unit| unit.text.as_str())
        .collect();
    equivalent_class_chars(&text)
        .into_iter()
        .any(|candidate| {
            let contained = ranges
                .iter()
                .any(|(low, high)| *low <= candidate && candidate <= *high);
            contained != negated
        })
        .then_some(end)
}

fn equivalent_class_chars(text: &str) -> Vec<char> {
    let composed: String = text.nfc().collect();
    let variants = [
        composed.clone(),
        composed.to_lowercase(),
        composed.to_uppercase(),
        composed.nfd().case_fold().nfc().collect(),
    ];
    let mut result = Vec::new();
    for variant in variants {
        let mut chars = variant.chars();
        if let (Some(ch), None) = (chars.next(), chars.next()) {
            if !result.contains(&ch) {
                result.push(ch);
            }
        }
    }
    result
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
        assert!(glob_matches_folded("[A].txt", "a.TXT"));
        assert!(glob_matches_folded("[A-Z].dat", "q.DAT"));
        assert!(glob_matches_folded("[!A-Z].dat", "q.DAT"));
        assert!(glob_matches_folded("[\u{c9}].txt", "\u{e9}.TXT"));
        assert!(glob_matches_folded("[A-f].txt", "Z.TXT"));
        assert!(glob_matches_folded("[A-].txt", "a.TXT"));
        assert!(!glob_matches_folded("[A-].txt", "_.TXT"));
        assert!(glob_matches_folded("*.{txt,md}", "README.MD"));
        assert!(!glob_matches_folded("!readme.txt", "README.TXT"));
        assert!(glob_matches_folded("!readme.txt", "other.txt"));
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
