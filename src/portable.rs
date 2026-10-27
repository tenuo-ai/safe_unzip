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
    let exact = glob_match::glob_match(positive, name);
    let equivalent = equivalent_glob_match(positive, name);
    if !exact && equivalent == EquivalentMatch::Indeterminate {
        // Exclusions are a safety boundary. If a deliberately pathological
        // pattern/name would exceed the bounded equivalence search, exclude it
        // rather than allow a normalization variant to bypass the filter.
        return true;
    }
    let matched = exact || equivalent == EquivalentMatch::Match;
    if negations % 2 == 1 {
        !matched
    } else {
        matched
    }
}

fn fold_for_glob(s: &str) -> String {
    s.nfd().case_fold().nfd().collect()
}

#[derive(Debug, Clone)]
enum GlobToken {
    Literal(String),
    Separator,
    Any,
    Star,
    DoubleStar,
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
    ch: char,
    separator: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EquivalentMatch {
    Match,
    NoMatch,
    Indeterminate,
}

const MAX_BRACE_EXPANSIONS: usize = 4_096;
const MAX_CANONICAL_VARIANTS: usize = 256;
const MAX_MATCH_ATTEMPTS: usize = 65_536;

/// Match a glob against any case- or normalization-equivalent spelling of a
/// name. This is deliberately token-aware: folding raw glob text can change a
/// range (`[A-f]`), turn a literal hyphen into a range, or split one Unicode
/// class member into several code points.
fn equivalent_glob_match(pattern: &str, name: &str) -> EquivalentMatch {
    let Some(tokens) = tokenize_glob(pattern) else {
        return EquivalentMatch::NoMatch;
    };
    let Some(unit_sets) = canonical_name_variants(name) else {
        return EquivalentMatch::Indeterminate;
    };
    match_expansions(&tokens, &unit_sets)
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
                if *i - start >= 2 {
                    // Whether this is a whole-component globstar depends on
                    // the selected brace branches. Classify it only after a
                    // concrete branch has been chosen.
                    tokens.push(GlobToken::DoubleStar);
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

/// Enumerate the canonically equivalent orderings of the folded name.
/// Combining marks with the same class retain their relative order, while
/// marks from different classes may interleave. The bound keeps malicious
/// names from causing combinatorial work.
fn canonical_name_variants(name: &str) -> Option<Vec<Vec<NameUnit>>> {
    let mut clusters: Vec<Vec<char>> = Vec::new();
    for ch in fold_for_glob(name).chars() {
        if canonical_combining_class(ch) == 0 || clusters.is_empty() {
            clusters.push(Vec::new());
        }
        clusters.last_mut().unwrap().push(ch);
    }

    let mut variants = vec![Vec::new()];
    for cluster in clusters {
        let cluster_variants = canonical_cluster_variants(&cluster)?;
        if variants.len().checked_mul(cluster_variants.len())? > MAX_CANONICAL_VARIANTS {
            return None;
        }
        let mut combined = Vec::with_capacity(variants.len() * cluster_variants.len());
        for prefix in &variants {
            for suffix in &cluster_variants {
                let mut spelling = Vec::with_capacity(prefix.len() + suffix.len());
                spelling.extend_from_slice(prefix);
                spelling.extend_from_slice(suffix);
                combined.push(spelling);
            }
        }
        variants = combined;
    }

    Some(
        variants
            .into_iter()
            .map(|variant| {
                variant
                    .into_iter()
                    .map(|ch| NameUnit {
                        ch,
                        separator: ch == '/',
                    })
                    .collect()
            })
            .collect(),
    )
}

fn canonical_cluster_variants(cluster: &[char]) -> Option<Vec<Vec<char>>> {
    if cluster.is_empty() {
        return Some(vec![Vec::new()]);
    }

    let starter = (canonical_combining_class(cluster[0]) == 0).then_some(cluster[0]);
    let marks = &cluster[usize::from(starter.is_some())..];
    let mut groups: Vec<(u8, Vec<char>)> = Vec::new();
    for &mark in marks {
        let class = canonical_combining_class(mark);
        if let Some((_, group)) = groups.iter_mut().find(|(existing, _)| *existing == class) {
            group.push(mark);
        } else {
            groups.push((class, vec![mark]));
        }
    }

    let mut positions = vec![0; groups.len()];
    let mut suffix = Vec::with_capacity(marks.len());
    let mut results = Vec::new();
    interleave_combining_groups(&groups, &mut positions, &mut suffix, &mut results)?;
    if let Some(starter) = starter {
        for result in &mut results {
            result.insert(0, starter);
        }
    }
    Some(results)
}

fn interleave_combining_groups(
    groups: &[(u8, Vec<char>)],
    positions: &mut [usize],
    current: &mut Vec<char>,
    results: &mut Vec<Vec<char>>,
) -> Option<()> {
    if positions
        .iter()
        .zip(groups)
        .all(|(position, (_, group))| *position == group.len())
    {
        if results.len() == MAX_CANONICAL_VARIANTS {
            return None;
        }
        results.push(current.clone());
        return Some(());
    }

    for group_index in 0..groups.len() {
        let position = positions[group_index];
        if position < groups[group_index].1.len() {
            current.push(groups[group_index].1[position]);
            positions[group_index] += 1;
            interleave_combining_groups(groups, positions, current, results)?;
            positions[group_index] -= 1;
            current.pop();
        }
    }
    Some(())
}

fn match_expansions(tokens: &[GlobToken], unit_sets: &[Vec<NameUnit>]) -> EquivalentMatch {
    let mut current = Vec::new();
    let mut expansions = 0;
    let mut attempts = 0;
    walk_expansions(
        vec![(tokens, 0)],
        &mut current,
        unit_sets,
        &mut expansions,
        &mut attempts,
    )
}

fn walk_expansions(
    mut stack: Vec<(&[GlobToken], usize)>,
    current: &mut Vec<GlobToken>,
    unit_sets: &[Vec<NameUnit>],
    expansions: &mut usize,
    attempts: &mut usize,
) -> EquivalentMatch {
    while stack
        .last()
        .is_some_and(|(sequence, index)| *index == sequence.len())
    {
        stack.pop();
    }

    let Some((sequence, index)) = stack.last().copied() else {
        if *expansions == MAX_BRACE_EXPANSIONS {
            return EquivalentMatch::Indeterminate;
        }
        *expansions += 1;
        let concrete = classify_globstars(current);
        for units in unit_sets {
            if *attempts == MAX_MATCH_ATTEMPTS {
                return EquivalentMatch::Indeterminate;
            }
            *attempts += 1;
            if match_tokens(&concrete, units) {
                return EquivalentMatch::Match;
            }
        }
        return EquivalentMatch::NoMatch;
    };
    stack.last_mut().unwrap().1 += 1;

    match &sequence[index] {
        GlobToken::Alternatives(alternatives) => {
            for alternative in alternatives {
                let mut branch = stack.clone();
                branch.push((alternative, 0));
                match walk_expansions(branch, current, unit_sets, expansions, attempts) {
                    EquivalentMatch::NoMatch => {}
                    result => return result,
                }
            }
            EquivalentMatch::NoMatch
        }
        token => {
            current.push(token.clone());
            let result = walk_expansions(stack, current, unit_sets, expansions, attempts);
            current.pop();
            result
        }
    }
}

fn classify_globstars(tokens: &[GlobToken]) -> Vec<GlobToken> {
    let mut concrete = Vec::with_capacity(tokens.len());
    let mut index = 0;
    while index < tokens.len() {
        if matches!(tokens[index], GlobToken::DoubleStar) {
            let component_start = index == 0 || matches!(tokens[index - 1], GlobToken::Separator);
            let component_end =
                index + 1 == tokens.len() || matches!(tokens[index + 1], GlobToken::Separator);
            if component_start && component_end {
                if index + 1 < tokens.len() {
                    concrete.push(GlobToken::GlobStarDirectory);
                    index += 2;
                } else {
                    concrete.push(GlobToken::GlobStar);
                    index += 1;
                }
            } else {
                concrete.push(GlobToken::Star);
                index += 1;
            }
        } else {
            debug_assert!(!matches!(tokens[index], GlobToken::Alternatives(_)));
            concrete.push(tokens[index].clone());
            index += 1;
        }
    }
    concrete
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
            GlobToken::DoubleStar | GlobToken::Alternatives(_) => {
                unreachable!("globstar classification and brace expansion happen before matching")
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
        actual.push(unit.ch);
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
        text.push(unit.ch);
        let mut composed = text.nfc();
        if composed.next().is_some() && composed.next().is_none() {
            ends.push(start + offset + 1);
        } else if offset > 0 && canonical_combining_class(unit.ch) == 0 {
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
            let text: String = units[start..*end].iter().map(|unit| unit.ch).collect();
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
        assert!(glob_matches_folded("{**/foo,bar}", "FOO"));
        assert!(glob_matches_folded("{**/foo,bar}", "a/b/FOO"));
        assert!(glob_matches_folded("{**,other}/foo.txt", "FOO.TXT"));
        assert!(glob_matches_folded("{**,other}/foo.txt", "a/b/FOO.TXT"));
        assert!(glob_matches_folded("\u{e1}*.txt", "\u{e1}\u{327}.TXT"));
        assert!(glob_matches_folded("\u{e1}*.txt", "a\u{327}\u{301}.TXT"));
        assert!(glob_matches_folded(
            "a\u{327}\u{301}*.txt",
            "a\u{327}\u{328}\u{301}.TXT"
        ));
        assert!(glob_matches_folded(
            "a\u{301}*\u{301}.txt",
            "a\u{327}\u{301}\u{301}.TXT"
        ));
        assert!(glob_matches_folded(
            "{x\u{327}*,\u{e1}*}.txt",
            "a\u{327}\u{301}.TXT"
        ));
        assert!(glob_matches_folded(
            "x\u{327}*/\u{e1}*.txt",
            "x\u{327}/a\u{327}\u{301}.TXT"
        ));
        assert!(!glob_matches_folded(
            "a\u{328}\u{327}*.txt",
            "a\u{327}\u{328}\u{301}.TXT"
        ));
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
