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
    Alternatives(Vec<Vec<GlobToken>>),
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
    let Some(tokens) = tokenize_glob(pattern) else {
        return false;
    };
    let unit_sets = [
        name_units(name),
        folded_name_units(name),
        locally_decomposed_name_units(name),
        pattern_ordered_name_units(name, &tokens),
    ];
    unit_sets.iter().any(|units| match_tokens(&tokens, units))
}

fn tokenize_glob(pattern: &str) -> Option<Vec<GlobToken>> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    let tokens = tokenize_sequence(&chars, &mut i, 0, false)?;
    (i == chars.len()).then_some(tokens)
}

fn tokenize_sequence(
    chars: &[char],
    i: &mut usize,
    depth: usize,
    in_brace: bool,
) -> Option<Vec<GlobToken>> {
    if depth > 10 {
        return None;
    }
    let mut tokens = Vec::new();
    let mut literal = String::new();

    while *i < chars.len() {
        if in_brace && matches!(chars[*i], ',' | '}') {
            break;
        }
        match chars[*i] {
            '\\' => {
                *i += 1;
                literal.push(*chars.get(*i)?);
                *i += 1;
            }
            '/' => {
                push_literal(&mut tokens, &mut literal);
                tokens.push(GlobToken::Separator);
                *i += 1;
            }
            '?' => {
                push_literal(&mut tokens, &mut literal);
                tokens.push(GlobToken::Any);
                *i += 1;
            }
            '*' => {
                push_literal(&mut tokens, &mut literal);
                let start = *i;
                while *i < chars.len() && chars[*i] == '*' {
                    *i += 1;
                }
                let is_component = *i - start >= 2
                    && (start == 0 || chars[start - 1] == '/')
                    && (*i == chars.len() || chars[*i] == '/');
                if is_component && *i < chars.len() {
                    // Consume the following slash. The whole `**/` segment is
                    // optional, as in the upstream glob matcher.
                    tokens.push(GlobToken::GlobStarDirectory);
                    *i += 1;
                } else if is_component {
                    tokens.push(GlobToken::GlobStar);
                } else {
                    tokens.push(GlobToken::Star);
                }
            }
            '[' => {
                push_literal(&mut tokens, &mut literal);
                let (token, next) = parse_class(chars, *i)?;
                tokens.push(token);
                *i = next;
            }
            '{' => {
                push_literal(&mut tokens, &mut literal);
                *i += 1;
                let mut alternatives = Vec::new();
                loop {
                    alternatives.push(tokenize_sequence(chars, i, depth + 1, true)?);
                    match chars.get(*i) {
                        Some(',') => *i += 1,
                        Some('}') => {
                            *i += 1;
                            break;
                        }
                        _ => return None,
                    }
                }
                tokens.push(GlobToken::Alternatives(alternatives));
            }
            c => {
                literal.push(c);
                *i += 1;
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

fn folded_name_units(name: &str) -> Vec<NameUnit> {
    fold_for_glob(name)
        .chars()
        .map(|ch| {
            let text = ch.to_string();
            NameUnit {
                folded: text.clone(),
                separator: text == "/",
                text,
            }
        })
        .collect()
}

/// Decompose each source scalar independently. Unlike whole-string NFD this
/// preserves a wildcard boundary before a following combining mark, while
/// still exposing the decomposed spelling of composed scalars.
fn locally_decomposed_name_units(name: &str) -> Vec<NameUnit> {
    name.chars()
        .flat_map(|ch| ch.to_string().nfd().collect::<Vec<_>>())
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

/// Put combining-mark groups required by literal tokens first within each
/// canonical cluster. Marks with the same combining class retain their order,
/// because swapping those would change the canonical-equivalence class.
fn pattern_ordered_name_units(name: &str, tokens: &[GlobToken]) -> Vec<NameUnit> {
    fn priorities(tokens: &[GlobToken], output: &mut Vec<char>) {
        for token in tokens {
            match token {
                GlobToken::Literal(literal) => {
                    for ch in literal.chars() {
                        if canonical_combining_class(ch) != 0 && !output.contains(&ch) {
                            output.push(ch);
                        }
                    }
                }
                GlobToken::Alternatives(alternatives) => {
                    for alternative in alternatives {
                        priorities(alternative, output);
                    }
                }
                _ => {}
            }
        }
    }

    fn push_cluster(cluster: &mut Vec<char>, priority: &[char], output: &mut Vec<char>) {
        if cluster.is_empty() {
            return;
        }
        output.push(cluster[0]);
        let mut groups: Vec<(u8, Vec<char>)> = Vec::new();
        for ch in cluster.drain(1..) {
            let class = canonical_combining_class(ch);
            if let Some((_, group)) = groups.iter_mut().find(|(existing, _)| *existing == class) {
                group.push(ch);
            } else {
                groups.push((class, vec![ch]));
            }
        }
        groups.sort_by_key(|(class, chars)| {
            let requested = chars
                .iter()
                .filter_map(|ch| priority.iter().position(|wanted| wanted == ch))
                .min()
                .unwrap_or(usize::MAX);
            (requested, *class)
        });
        output.extend(groups.into_iter().flat_map(|(_, chars)| chars));
        cluster.clear();
    }

    let mut priority = Vec::new();
    priorities(tokens, &mut priority);
    let mut reordered = Vec::new();
    let mut cluster = Vec::new();
    for ch in fold_for_glob(name).chars() {
        if canonical_combining_class(ch) == 0 && !cluster.is_empty() {
            push_cluster(&mut cluster, &priority, &mut reordered);
        }
        cluster.push(ch);
    }
    push_cluster(&mut cluster, &priority, &mut reordered);

    reordered
        .into_iter()
        .map(|ch| {
            let text = ch.to_string();
            NameUnit {
                folded: text.clone(),
                separator: text == "/",
                text,
            }
        })
        .collect()
}

fn match_tokens(tokens: &[GlobToken], units: &[NameUnit]) -> bool {
    let mut tail = vec![false; units.len() + 1];
    tail[units.len()] = true;
    match_sequence(tokens, units, tail)[0]
}

fn match_sequence(tokens: &[GlobToken], units: &[NameUnit], mut next: Vec<bool>) -> Vec<bool> {
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
                    current[unit_index] = equivalent_character_ends(units, unit_index)
                        .into_iter()
                        .any(|end| next[end]);
                }
            }
            GlobToken::Class { negated, ranges } => {
                for unit_index in (0..units.len()).rev() {
                    current[unit_index] = class_match_ends(*negated, ranges, units, unit_index)
                        .into_iter()
                        .any(|end| next[end]);
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
            GlobToken::Alternatives(alternatives) => {
                for alternative in alternatives {
                    let alternative = match_sequence(alternative, units, next.clone());
                    for (matched, branch) in current.iter_mut().zip(alternative) {
                        *matched |= branch;
                    }
                }
            }
        }
        next = current;
    }
    next
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

fn equivalent_character_ends(units: &[NameUnit], start: usize) -> Vec<usize> {
    if units.get(start).is_none_or(|unit| unit.separator) {
        return Vec::new();
    }
    let mut text = String::new();
    let mut ends = Vec::new();
    for (offset, unit) in units[start..].iter().enumerate() {
        if unit.separator {
            break;
        }
        text.push_str(&unit.text);
        let mut composed = text.nfc();
        if composed.next().is_some() && composed.next().is_none() {
            ends.push(start + offset + 1);
        } else if offset > 0 && canonical_combining_class(unit.text.chars().next().unwrap()) == 0 {
            // Canonical composition never joins across two already-complete
            // starters. Hangul is the exception that reaches this point, and
            // successful L/V/T compositions were recorded above.
            break;
        }
    }
    ends
}

fn class_match_ends(
    negated: bool,
    ranges: &[(char, char)],
    units: &[NameUnit],
    start: usize,
) -> Vec<usize> {
    equivalent_character_ends(units, start)
        .into_iter()
        .filter(|end| {
            let text: String = units[start..*end]
                .iter()
                .map(|unit| unit.text.as_str())
                .collect();
            equivalent_class_chars(&text).into_iter().any(|candidate| {
                let contained = ranges
                    .iter()
                    .any(|(low, high)| *low <= candidate && candidate <= *high);
                contained != negated
            })
        })
        .collect()
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
        assert!(glob_matches_folded("??.txt", "\u{e9}.TXT"));
        assert!(glob_matches_folded("stras*.txt", "stra\u{df}e.TXT"));
        assert!(glob_matches_folded("?.txt", "\u{ac00}.TXT"));
        assert!(glob_matches_folded("?.txt", "\u{1100}\u{1161}.TXT"));
        assert!(glob_matches_folded(
            "[\u{ac00}].txt",
            "\u{1100}\u{1161}.TXT"
        ));
        let many_braces = format!("{}.txt", "{a,b}".repeat(9));
        assert!(glob_matches_folded(&many_braces, "AAAAAAAAA.TXT"));
        assert!(glob_matches_folded("\u{e1}*.txt", "\u{e1}\u{327}.TXT"));
        assert!(glob_matches_folded("\u{e1}*.txt", "a\u{327}\u{301}.TXT"));
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
