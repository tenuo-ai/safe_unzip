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
    let matched = if exact {
        true
    } else {
        match equivalent_glob_match(positive, name) {
            EquivalentMatch::Match => true,
            EquivalentMatch::NoMatch => false,
            EquivalentMatch::Indeterminate => {
                // Exclusions are a safety boundary. If a deliberately
                // pathological name exceeds the bounded equivalence search,
                // exclude it rather than allow a normalization bypass.
                return true;
            }
        }
    };
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
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
    Alternatives(Vec<Vec<GlobToken>>),
}

#[derive(Debug, Clone)]
struct NameUnit {
    ch: char,
    separator: bool,
    source: usize,
    source_char: char,
    source_total: usize,
    pre_unit: usize,
    pre_char: char,
    pre_total: usize,
}

#[derive(Debug)]
struct PreFoldUnit {
    ch: char,
    source: usize,
    source_char: char,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EquivalentMatch {
    Match,
    NoMatch,
    Indeterminate,
}

const MAX_CANONICAL_VARIANTS: usize = 256;
const MAX_COMBINING_MARKS_PER_CLUSTER: usize = 64;

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
    if unit_sets.iter().any(|units| match_tokens(&tokens, units)) {
        EquivalentMatch::Match
    } else {
        EquivalentMatch::NoMatch
    }
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
    let pre_fold = canonical_pre_fold_units(name)?;
    let mut base = Vec::new();
    let mut source_totals = vec![0; name.chars().count()];
    for (pre_unit, unit) in pre_fold.into_iter().enumerate() {
        let folded: Vec<char> = unit.ch.to_string().case_fold().nfd().collect();
        let pre_total = folded.len();
        source_totals[unit.source] += pre_total;
        for ch in folded {
            base.push(NameUnit {
                ch,
                separator: ch == '/',
                source: unit.source,
                source_char: unit.source_char,
                source_total: 0,
                pre_unit,
                pre_char: unit.ch,
                pre_total,
            });
        }
    }
    for unit in &mut base {
        unit.source_total = source_totals[unit.source];
    }

    let mut variants = vec![Vec::new()];
    let mut cluster = Vec::new();
    for unit in base {
        if canonical_combining_class(unit.ch) == 0 && !cluster.is_empty() {
            append_canonical_cluster(&mut variants, &cluster)?;
            cluster.clear();
        }
        cluster.push(unit);
        let mark_count = cluster.len() - usize::from(canonical_combining_class(cluster[0].ch) == 0);
        if mark_count > MAX_COMBINING_MARKS_PER_CLUSTER {
            return None;
        }
    }
    if !cluster.is_empty() {
        append_canonical_cluster(&mut variants, &cluster)?;
    }
    Some(variants)
}

fn canonical_pre_fold_units(name: &str) -> Option<Vec<PreFoldUnit>> {
    let mut result = Vec::new();
    let mut cluster = Vec::new();
    for (source, source_char) in name.chars().enumerate() {
        for ch in source_char.to_string().nfd() {
            if canonical_combining_class(ch) == 0 && !cluster.is_empty() {
                append_pre_fold_cluster(&mut result, &mut cluster);
            }
            cluster.push(PreFoldUnit {
                ch,
                source,
                source_char,
            });
            let mark_count =
                cluster.len() - usize::from(canonical_combining_class(cluster[0].ch) == 0);
            if mark_count > MAX_COMBINING_MARKS_PER_CLUSTER {
                return None;
            }
        }
    }
    append_pre_fold_cluster(&mut result, &mut cluster);
    Some(result)
}

fn append_pre_fold_cluster(result: &mut Vec<PreFoldUnit>, cluster: &mut Vec<PreFoldUnit>) {
    let mark_start = usize::from(
        cluster
            .first()
            .is_some_and(|unit| canonical_combining_class(unit.ch) == 0),
    );
    cluster[mark_start..].sort_by_key(|unit| canonical_combining_class(unit.ch));
    result.append(cluster);
}

fn append_canonical_cluster(variants: &mut Vec<Vec<NameUnit>>, cluster: &[NameUnit]) -> Option<()> {
    let cluster_variants = canonical_cluster_variants(cluster)?;
    if variants.len().checked_mul(cluster_variants.len())? > MAX_CANONICAL_VARIANTS {
        return None;
    }
    if cluster_variants.len() == 1 {
        let suffix = &cluster_variants[0];
        for prefix in variants {
            prefix.extend_from_slice(suffix);
        }
    } else {
        let prefixes = std::mem::take(variants);
        variants.reserve(prefixes.len() * cluster_variants.len());
        for prefix in prefixes {
            for suffix in &cluster_variants {
                let mut spelling = Vec::with_capacity(prefix.len() + suffix.len());
                spelling.extend_from_slice(&prefix);
                spelling.extend_from_slice(suffix);
                variants.push(spelling);
            }
        }
    }
    Some(())
}

fn canonical_cluster_variants(cluster: &[NameUnit]) -> Option<Vec<Vec<NameUnit>>> {
    if cluster.is_empty() {
        return Some(vec![Vec::new()]);
    }

    let starter = (canonical_combining_class(cluster[0].ch) == 0).then_some(&cluster[0]);
    let marks = &cluster[usize::from(starter.is_some())..];
    if marks.len() > MAX_COMBINING_MARKS_PER_CLUSTER {
        return None;
    }
    let mut groups: Vec<(u8, Vec<NameUnit>)> = Vec::new();
    for mark in marks {
        let class = canonical_combining_class(mark.ch);
        if let Some((_, group)) = groups.iter_mut().find(|(existing, _)| *existing == class) {
            group.push(mark.clone());
        } else {
            groups.push((class, vec![mark.clone()]));
        }
    }

    let mut positions = vec![0; groups.len()];
    let mut suffix = Vec::with_capacity(marks.len());
    let mut results = Vec::new();
    interleave_combining_groups(&groups, &mut positions, &mut suffix, &mut results)?;
    if let Some(starter) = starter {
        for result in &mut results {
            result.insert(0, starter.clone());
        }
    }
    Some(results)
}

fn interleave_combining_groups(
    groups: &[(u8, Vec<NameUnit>)],
    positions: &mut [usize],
    current: &mut Vec<NameUnit>,
    results: &mut Vec<Vec<NameUnit>>,
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
            current.push(groups[group_index].1[position].clone());
            positions[group_index] += 1;
            interleave_combining_groups(groups, positions, current, results)?;
            positions[group_index] -= 1;
            current.pop();
        }
    }
    Some(())
}

#[derive(Clone)]
struct MatchState {
    positions: Vec<bool>,
    component_start: bool,
    pending_stars: u8,
}

fn match_tokens(tokens: &[GlobToken], units: &[NameUnit]) -> bool {
    let mut positions = vec![false; units.len() + 1];
    positions[0] = true;
    let states = advance_sequence(
        tokens,
        vec![MatchState {
            positions,
            component_start: true,
            pending_stars: 0,
        }],
        units,
    );
    finish_states(states, units)
        .iter()
        .any(|state| state.positions[units.len()])
}

fn advance_sequence(
    tokens: &[GlobToken],
    mut states: Vec<MatchState>,
    units: &[NameUnit],
) -> Vec<MatchState> {
    for token in tokens {
        states = match token {
            GlobToken::Star | GlobToken::DoubleStar => {
                let count = if matches!(token, GlobToken::DoubleStar) {
                    2
                } else {
                    1
                };
                for state in &mut states {
                    state.pending_stars = state.pending_stars.saturating_add(count).min(2);
                }
                states
            }
            GlobToken::Alternatives(alternatives) => {
                let mut branches = Vec::new();
                for state in states {
                    for alternative in alternatives {
                        branches.extend(advance_sequence(alternative, vec![state.clone()], units));
                    }
                }
                merge_states(branches)
            }
            _ => advance_nonstar(token, states, units),
        };
    }
    states
}

fn advance_nonstar(
    token: &GlobToken,
    states: Vec<MatchState>,
    units: &[NameUnit],
) -> Vec<MatchState> {
    let mut advanced = Vec::new();
    for mut state in states {
        if state.pending_stars >= 2
            && state.component_start
            && matches!(token, GlobToken::Separator)
        {
            state.positions = globstar_directory_positions(&state.positions, units);
            state.pending_stars = 0;
            state.component_start = true;
            advanced.push(state);
            continue;
        }
        if state.pending_stars > 0 {
            state.positions = star_positions(&state.positions, units, false);
            state.pending_stars = 0;
        }
        state.positions = token_positions(token, &state.positions, units);
        state.component_start = matches!(token, GlobToken::Separator);
        advanced.push(state);
    }
    merge_states(advanced)
}

fn finish_states(states: Vec<MatchState>, units: &[NameUnit]) -> Vec<MatchState> {
    let mut finished = Vec::new();
    for mut state in states {
        if state.pending_stars > 0 {
            let crosses_separators = state.pending_stars >= 2 && state.component_start;
            state.positions = star_positions(&state.positions, units, crosses_separators);
            state.pending_stars = 0;
        }
        finished.push(state);
    }
    merge_states(finished)
}

fn merge_states(states: Vec<MatchState>) -> Vec<MatchState> {
    let mut merged: Vec<MatchState> = Vec::new();
    for state in states {
        if let Some(existing) = merged.iter_mut().find(|existing| {
            existing.component_start == state.component_start
                && existing.pending_stars == state.pending_stars
        }) {
            for (target, source) in existing.positions.iter_mut().zip(state.positions) {
                *target |= source;
            }
        } else {
            merged.push(state);
        }
    }
    merged
}

fn token_positions(token: &GlobToken, positions: &[bool], units: &[NameUnit]) -> Vec<bool> {
    let mut next = vec![false; units.len() + 1];
    for (start, matched) in positions.iter().copied().enumerate() {
        if !matched || start == units.len() {
            continue;
        }
        match token {
            GlobToken::Literal(expected) => {
                if let Some(end) = consume_literal(expected, units, start) {
                    next[end] = true;
                }
            }
            GlobToken::Separator => {
                if units[start].separator {
                    next[start + 1] = true;
                }
            }
            GlobToken::Any => {
                for end in equivalent_character_ends(units, start) {
                    next[end] = true;
                }
            }
            GlobToken::Class { negated, ranges } => {
                for end in class_match_ends(*negated, ranges, units, start) {
                    next[end] = true;
                }
            }
            GlobToken::Star | GlobToken::DoubleStar | GlobToken::Alternatives(_) => {
                unreachable!("handled before primitive token matching")
            }
        }
    }
    next
}

fn star_positions(positions: &[bool], units: &[NameUnit], crosses_separators: bool) -> Vec<bool> {
    let mut next = vec![false; positions.len()];
    let mut reachable = false;
    for index in 0..positions.len() {
        reachable |= positions[index];
        next[index] = reachable;
        if index < units.len() && units[index].separator && !crosses_separators {
            reachable = false;
        }
    }
    next
}

fn globstar_directory_positions(positions: &[bool], units: &[NameUnit]) -> Vec<bool> {
    let mut next = positions.to_vec();
    let mut reachable = false;
    for index in 0..units.len() {
        reachable |= positions[index];
        if reachable && units[index].separator {
            next[index + 1] = true;
        }
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
        let end = start + offset + 1;
        let mut composed = text.nfc();
        if (composed.next().is_some() && composed.next().is_none())
            || original_scalar(units, start, end).is_some()
            || pre_fold_scalar(units, start, end).is_some()
        {
            ends.push(end);
        } else if offset > 0
            && canonical_combining_class(unit.ch) == 0
            && !incomplete_source_scalar(units, start, end)
            && !incomplete_pre_fold_unit(units, start, end)
        {
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
            let mut candidates = equivalent_class_chars(&text);
            if let Some(original) = original_scalar(units, start, *end) {
                for candidate in equivalent_class_chars(&original.to_string()) {
                    if !candidates.contains(&candidate) {
                        candidates.push(candidate);
                    }
                }
            }
            if let Some(pre_fold) = pre_fold_scalar(units, start, *end) {
                for candidate in equivalent_class_chars(&pre_fold.to_string()) {
                    if !candidates.contains(&candidate) {
                        candidates.push(candidate);
                    }
                }
            }
            candidates.into_iter().any(|candidate| {
                let contained = ranges
                    .iter()
                    .any(|(low, high)| *low <= candidate && candidate <= *high);
                contained != negated
            })
        })
        .collect()
}

fn original_scalar(units: &[NameUnit], start: usize, end: usize) -> Option<char> {
    let slice = units.get(start..end)?;
    let first = slice.first()?;
    (slice.len() == first.source_total && slice.iter().all(|unit| unit.source == first.source))
        .then_some(first.source_char)
}

fn incomplete_source_scalar(units: &[NameUnit], start: usize, end: usize) -> bool {
    let Some(slice) = units.get(start..end) else {
        return false;
    };
    let Some(first) = slice.first() else {
        return false;
    };
    slice.len() < first.source_total && slice.iter().all(|unit| unit.source == first.source)
}

fn incomplete_pre_fold_unit(units: &[NameUnit], start: usize, end: usize) -> bool {
    let Some(slice) = units.get(start..end) else {
        return false;
    };
    let Some(first) = slice.first() else {
        return false;
    };
    slice.len() < first.pre_total && slice.iter().all(|unit| unit.pre_unit == first.pre_unit)
}

fn pre_fold_scalar(units: &[NameUnit], start: usize, end: usize) -> Option<char> {
    let slice = units.get(start..end)?;
    let mut pre_units: Vec<(usize, char, usize, usize)> = Vec::new();
    for unit in slice {
        if let Some((_, _, _, count)) = pre_units
            .iter_mut()
            .find(|(pre_unit, _, _, _)| *pre_unit == unit.pre_unit)
        {
            *count += 1;
        } else {
            pre_units.push((unit.pre_unit, unit.pre_char, unit.pre_total, 1));
        }
    }
    if pre_units.iter().any(|(_, _, total, count)| total != count) {
        return None;
    }
    pre_units.sort_by_key(|(pre_unit, _, _, _)| *pre_unit);
    if pre_units
        .windows(2)
        .any(|pair| pair[0].0.checked_add(1) != Some(pair[1].0))
    {
        return None;
    }
    let text: String = pre_units
        .into_iter()
        .map(|(_, pre_char, _, _)| pre_char)
        .collect();
    let mut composed = text.nfc();
    match (composed.next(), composed.next()) {
        (Some(ch), None) => Some(ch),
        _ => None,
    }
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
        assert!(glob_matches_folded("?.txt", "\u{df}.TXT"));
        assert!(glob_matches_folded("[\u{df}].txt", "\u{df}.TXT"));
        assert!(glob_matches_folded("[\u{df}].txt", "\u{1e9e}.TXT"));
        assert!(glob_matches_folded("?.txt", "I\u{307}.TXT"));
        assert!(glob_matches_folded("[\u{130}].txt", "I\u{307}.TXT"));
        assert!(glob_matches_folded("?.txt", "\u{fb03}.TXT"));
        assert!(glob_matches_folded("[\u{fb03}].txt", "\u{fb03}.TXT"));
        assert!(glob_matches_folded("?.txt", "\u{fb04}.TXT"));
        assert!(glob_matches_folded("[\u{fb04}].txt", "\u{fb04}.TXT"));
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
        assert!(glob_matches_folded("{*,x}*/foo.txt", "a/b/FOO.TXT"));
        let many_independent_braces = format!("{}.txt", "{a,b}".repeat(13));
        assert!(!glob_matches_folded(
            &many_independent_braces,
            "unrelated.rs"
        ));
        assert!(glob_matches_folded(
            "\u{3b1}\u{301}\u{345}.txt",
            "\u{3b1}\u{345}\u{301}.TXT"
        ));
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
        assert!(!glob_matches_folded(
            "[\u{1e69}]\u{323}.txt",
            "\u{1e69}.TXT"
        ));
        assert!(!glob_matches_folded("**/.git/**", "x/git/config"));
    }

    #[test]
    fn canonical_variant_generation_is_bounded_and_linear_for_simple_names() {
        let long_ascii_name = "a".repeat(65_535);
        let variants = canonical_name_variants(&long_ascii_name).unwrap();
        assert_eq!(variants.len(), 1);
        assert_eq!(variants[0].len(), long_ascii_name.len());

        let too_many_marks = format!("a{}", "\u{301}".repeat(MAX_COMBINING_MARKS_PER_CLUSTER + 1));
        assert!(canonical_name_variants(&too_many_marks).is_none());

        let expensive_if_folded = format!("{}{}", "a\u{327}\u{301}".repeat(8), "z".repeat(60_000));
        assert!(glob_matches_folded("*", &expensive_if_folded));
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
