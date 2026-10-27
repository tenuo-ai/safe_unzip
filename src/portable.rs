//! Filename rules that hold across filesystems.
//!
//! Extraction may target case-insensitive or Unicode-normalizing filesystems
//! (macOS, Windows) and Windows, which drops trailing dots and spaces from
//! names. These helpers treat names that refer to the same file there as
//! equivalent, and reject names whose meaning changes between platforms.

use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::char::canonical_combining_class;
use unicode_normalization::UnicodeNormalization;

use std::collections::HashSet;

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct NameUnit {
    ch: char,
    separator: bool,
    source: usize,
    source_char: char,
    source_total: usize,
    pre_unit: usize,
    pre_char: char,
    pre_total: usize,
    pre_offset: usize,
    canonical_rank: u16,
}

#[derive(Debug, Clone)]
struct PreFoldUnit {
    ch: char,
    source: usize,
    source_char: char,
    id: usize,
}

#[derive(Debug, Clone)]
struct NameEdge {
    unit: NameUnit,
    target: usize,
}

#[derive(Debug)]
struct NameGraph {
    edges: Vec<Vec<NameEdge>>,
    cluster_boundaries: Vec<bool>,
    edge_count: usize,
    end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EquivalentMatch {
    Match,
    NoMatch,
    Indeterminate,
}

const MAX_CANONICAL_CLUSTER_VARIANTS: usize = 256;
const MAX_EQUIVALENT_PRE_FOLD_SPELLINGS: usize = 256;
const MAX_COMBINING_MARKS_PER_CLUSTER: usize = 64;
const MAX_NAME_GRAPH_ITEMS: usize = 65_536;
const MAX_MATCH_STATES: usize = 1_024;
const MAX_PENDING_PROBE_STATES: usize = 4_096;

/// Match a glob against any case- or normalization-equivalent spelling of a
/// name. This is deliberately token-aware: folding raw glob text can change a
/// range (`[A-f]`), turn a literal hyphen into a range, or split one Unicode
/// class member into several code points.
fn equivalent_glob_match(pattern: &str, name: &str) -> EquivalentMatch {
    if !name_within_equivalence_limits(name) {
        return EquivalentMatch::Indeterminate;
    }
    let Some(tokens) = tokenize_glob(pattern) else {
        return EquivalentMatch::NoMatch;
    };
    if let Some(literal) = literal_pattern(&tokens) {
        return if fold_for_glob(&literal) == fold_for_glob(name) {
            EquivalentMatch::Match
        } else {
            EquivalentMatch::NoMatch
        };
    }
    let linear = linear_folded_name_graph(name);
    match match_tokens(&tokens, &linear, false) {
        Some(true) => return EquivalentMatch::Match,
        Some(false) => {}
        None => return EquivalentMatch::Indeterminate,
    }
    if let Some(suffix) = ascii_literal_suffix(&tokens) {
        if !fold_for_glob(name).ends_with(&suffix) {
            return EquivalentMatch::NoMatch;
        }
    }
    if literal_only(&tokens) {
        return EquivalentMatch::NoMatch;
    }
    let Some(graphs) = canonical_name_graphs(name, &tokens) else {
        return EquivalentMatch::Indeterminate;
    };
    let mut indeterminate = false;
    for graph in graphs {
        match match_tokens(&tokens, &graph, true) {
            Some(true) => return EquivalentMatch::Match,
            Some(false) => {}
            None => indeterminate = true,
        }
    }
    if indeterminate {
        EquivalentMatch::Indeterminate
    } else {
        EquivalentMatch::NoMatch
    }
}

fn name_within_equivalence_limits(name: &str) -> bool {
    let mut marks_in_cluster = 0;
    let mut folded_units = 0;
    for source_char in name.chars() {
        let source = source_char.to_string();
        for ch in source.nfd() {
            if canonical_combining_class(ch) == 0 {
                marks_in_cluster = 0;
            } else {
                marks_in_cluster += 1;
                if marks_in_cluster > MAX_COMBINING_MARKS_PER_CLUSTER {
                    return false;
                }
            }

            let decomposed = ch.to_string();
            for _ in decomposed.case_fold().nfd() {
                folded_units += 1;
                if folded_units >= MAX_NAME_GRAPH_ITEMS {
                    return false;
                }
            }
        }
    }
    true
}

fn literal_only(tokens: &[GlobToken]) -> bool {
    tokens.iter().all(|token| match token {
        GlobToken::Literal(_) | GlobToken::Separator => true,
        GlobToken::Alternatives(alternatives) => alternatives
            .iter()
            .all(|alternative| literal_only(alternative)),
        _ => false,
    })
}

fn ascii_literal_suffix(tokens: &[GlobToken]) -> Option<String> {
    let mut parts = Vec::new();
    for token in tokens.iter().rev() {
        match token {
            GlobToken::Literal(literal) if literal.is_ascii() => parts.push(literal.as_str()),
            GlobToken::Separator => parts.push("/"),
            _ => break,
        }
    }
    if parts.is_empty() {
        return None;
    }
    parts.reverse();
    Some(parts.concat().to_ascii_lowercase())
}

fn literal_pattern(tokens: &[GlobToken]) -> Option<String> {
    let mut literal = String::new();
    for token in tokens {
        match token {
            GlobToken::Literal(fragment) => literal.push_str(fragment),
            GlobToken::Separator => literal.push('/'),
            _ => return None,
        }
    }
    Some(literal)
}

fn linear_folded_name_graph(name: &str) -> NameGraph {
    let mut units = Vec::new();
    let mut boundary_indexes = Vec::new();
    for mut cluster in
        pre_fold_clusters(name).expect("name limits are checked before graph construction")
    {
        cluster.sort_by_key(|unit| canonical_combining_class(unit.ch));
        let mut folded = folded_units(&cluster);
        canonicalize_folded_units(&mut folded);
        for (rank, unit) in folded.iter_mut().enumerate() {
            unit.canonical_rank = u16::try_from(rank).unwrap_or(u16::MAX - 1);
        }
        units.extend(folded);
        boundary_indexes.push(units.len());
    }
    let mut edges = vec![Vec::new(); units.len() + 1];
    let mut cluster_boundaries = vec![false; units.len() + 1];
    cluster_boundaries[0] = true;
    for boundary in boundary_indexes {
        cluster_boundaries[boundary] = true;
    }
    for (index, unit) in units.into_iter().enumerate() {
        edges[index].push(NameEdge {
            unit,
            target: index + 1,
        });
    }
    NameGraph {
        cluster_boundaries,
        edge_count: edges.len().saturating_sub(1),
        end: edges.len().saturating_sub(1),
        edges,
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
        tokens.push(GlobToken::Literal(std::mem::take(literal)));
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
fn canonical_name_graph(name: &str) -> Option<NameGraph> {
    let mut graph = NameGraph {
        edges: vec![Vec::new()],
        cluster_boundaries: vec![true],
        edge_count: 0,
        end: 0,
    };
    for cluster in pre_fold_clusters(name)? {
        append_pre_fold_cluster(&mut graph, &cluster)?;
    }
    Some(graph)
}

fn canonical_name_graphs(name: &str, tokens: &[GlobToken]) -> Option<Vec<NameGraph>> {
    let original = canonical_name_graph(name)?;
    let mut total_edges = original.edge_count;
    let mut graphs = vec![original];
    let folded = fold_for_glob(name);
    if !folded.contains('\u{3b9}') {
        return Some(graphs);
    }
    let spelling_demand = iota_spelling_demand(tokens);
    if spelling_demand == 0 {
        return Some(graphs);
    }
    let original: Vec<char> = name.chars().collect();
    let iota_indexes: Vec<usize> = original
        .iter()
        .enumerate()
        .filter_map(|(index, ch)| (fold_for_glob(&ch.to_string()) == "\u{3b9}").then_some(index))
        .collect();
    let mut replacements: Vec<Vec<usize>> = vec![Vec::new()];
    for index in iota_indexes {
        let existing = replacements.len();
        for replacement in 0..existing {
            if replacements[replacement].len() < spelling_demand {
                if replacements.len() == MAX_EQUIVALENT_PRE_FOLD_SPELLINGS {
                    return None;
                }
                let mut replacement = replacements[replacement].clone();
                replacement.push(index);
                replacements.push(replacement);
            }
        }
    }
    for replacement in replacements.into_iter().skip(1) {
        let mut spelling = original.clone();
        for index in replacement {
            spelling[index] = '\u{345}';
        }
        let spelling: String = spelling.into_iter().collect();
        if fold_for_glob(&spelling) != folded {
            continue;
        }
        let graph = canonical_name_graph(&spelling)?;
        total_edges = total_edges.checked_add(graph.edge_count)?;
        if total_edges > MAX_NAME_GRAPH_ITEMS {
            return None;
        }
        graphs.push(graph);
    }
    Some(graphs)
}

fn iota_spelling_demand(tokens: &[GlobToken]) -> usize {
    tokens.iter().fold(0usize, |demand, token| {
        demand.saturating_add(match token {
            GlobToken::Literal(literal) => literal
                .chars()
                .filter(|ch| char_decomposes_to_iota_subscript(*ch))
                .count(),
            GlobToken::Any => 1,
            GlobToken::Star | GlobToken::DoubleStar => MAX_EQUIVALENT_PRE_FOLD_SPELLINGS,
            GlobToken::Class { negated, ranges } => usize::from(
                *negated
                    || ranges
                        .iter()
                        .any(|(low, high)| range_contains_iota_subscript(*low, *high)),
            ),
            GlobToken::Alternatives(alternatives) => alternatives
                .iter()
                .map(|alternative| iota_spelling_demand(alternative))
                .max()
                .unwrap_or(0),
            GlobToken::Separator => 0,
        })
    })
}

fn range_contains_iota_subscript(low: char, high: char) -> bool {
    const DECOMPOSITION_RANGES: &[(char, char)] = &[
        ('\u{345}', '\u{345}'),
        ('\u{1f80}', '\u{1faf}'),
        ('\u{1fb2}', '\u{1fb4}'),
        ('\u{1fb7}', '\u{1fb7}'),
        ('\u{1fbc}', '\u{1fbc}'),
        ('\u{1fc2}', '\u{1fc4}'),
        ('\u{1fc7}', '\u{1fc7}'),
        ('\u{1fcc}', '\u{1fcc}'),
        ('\u{1ff2}', '\u{1ff4}'),
        ('\u{1ff7}', '\u{1ff7}'),
        ('\u{1ffc}', '\u{1ffc}'),
    ];
    DECOMPOSITION_RANGES
        .iter()
        .any(|(range_low, range_high)| low <= *range_high && high >= *range_low)
}

fn char_decomposes_to_iota_subscript(ch: char) -> bool {
    ch.to_string().nfd().any(|part| part == '\u{345}')
}

fn pre_fold_clusters(name: &str) -> Option<Vec<Vec<PreFoldUnit>>> {
    let mut result = Vec::new();
    let mut cluster = Vec::new();
    let mut id = 0;
    for (source, source_char) in name.chars().enumerate() {
        for ch in source_char.to_string().nfd() {
            if canonical_combining_class(ch) == 0 && !cluster.is_empty() {
                result.push(std::mem::take(&mut cluster));
            }
            cluster.push(PreFoldUnit {
                ch,
                source,
                source_char,
                id,
            });
            id += 1;
            let mark_count =
                cluster.len() - usize::from(canonical_combining_class(cluster[0].ch) == 0);
            if mark_count > MAX_COMBINING_MARKS_PER_CLUSTER {
                return None;
            }
        }
    }
    if !cluster.is_empty() {
        result.push(cluster);
    }
    Some(result)
}

fn append_pre_fold_cluster(graph: &mut NameGraph, cluster: &[PreFoldUnit]) -> Option<()> {
    let variants = pre_fold_cluster_variants(cluster)?;
    let mut linear_ids: Vec<usize> = cluster.iter().map(|unit| unit.id).collect();
    let mark_start = usize::from(
        cluster
            .first()
            .is_some_and(|unit| canonical_combining_class(unit.ch) == 0),
    );
    linear_ids[mark_start..]
        .sort_by_key(|id| canonical_combining_class(cluster[*id - cluster[0].id].ch));
    let linear_units = folded_units(
        &linear_ids
            .iter()
            .map(|id| cluster[*id - cluster[0].id].clone())
            .collect::<Vec<_>>(),
    );
    let mut canonical_units = linear_units.clone();
    canonicalize_folded_units(&mut canonical_units);
    let ranks: Vec<(usize, usize)> = canonical_units
        .iter()
        .map(|unit| (unit.pre_unit, unit.pre_offset))
        .collect();
    let start = graph.end;
    let end = add_graph_node(graph)?;
    for variant in variants {
        let mut folded = folded_units(&variant);
        for unit in &mut folded {
            let rank = ranks
                .iter()
                .position(|identity| *identity == (unit.pre_unit, unit.pre_offset))?;
            unit.canonical_rank = u16::try_from(rank).ok()?;
        }
        append_folded_sequence(graph, start, end, &folded)?;
    }
    graph.cluster_boundaries[end] = true;
    graph.end = end;
    Some(())
}

fn folded_units(variant: &[PreFoldUnit]) -> Vec<NameUnit> {
    let mut folded = Vec::new();
    for unit in variant {
        let chars: Vec<char> = unit.ch.to_string().case_fold().nfd().collect();
        let pre_total = chars.len();
        let source_total = unit.source_char.to_string().nfd().case_fold().nfd().count();
        for (pre_offset, ch) in chars.into_iter().enumerate() {
            folded.push(NameUnit {
                ch,
                separator: ch == '/',
                source: unit.source,
                source_char: unit.source_char,
                source_total,
                pre_unit: unit.id,
                pre_char: unit.ch,
                pre_total,
                pre_offset,
                canonical_rank: 0,
            });
        }
    }
    folded
}

fn canonicalize_folded_units(units: &mut [NameUnit]) {
    let mut start = 0;
    while start < units.len() {
        let mut end = start + 1;
        while end < units.len() && canonical_combining_class(units[end].ch) != 0 {
            end += 1;
        }
        let mark_start = start + usize::from(canonical_combining_class(units[start].ch) == 0);
        units[mark_start..end].sort_by_key(|unit| canonical_combining_class(unit.ch));
        start = end;
    }
}

fn pre_fold_cluster_variants(cluster: &[PreFoldUnit]) -> Option<Vec<Vec<PreFoldUnit>>> {
    if cluster.is_empty() {
        return Some(vec![Vec::new()]);
    }
    let starter = (canonical_combining_class(cluster[0].ch) == 0).then_some(&cluster[0]);
    let marks = &cluster[usize::from(starter.is_some())..];
    let mut groups: Vec<(u8, Vec<PreFoldUnit>)> = Vec::new();
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
    interleave_pre_fold_groups(&groups, &mut positions, &mut suffix, &mut results)?;
    if let Some(starter) = starter {
        for result in &mut results {
            result.insert(0, starter.clone());
        }
    }
    Some(results)
}

fn interleave_pre_fold_groups(
    groups: &[(u8, Vec<PreFoldUnit>)],
    positions: &mut [usize],
    current: &mut Vec<PreFoldUnit>,
    results: &mut Vec<Vec<PreFoldUnit>>,
) -> Option<()> {
    if positions
        .iter()
        .zip(groups)
        .all(|(position, (_, group))| *position == group.len())
    {
        if results.len() == MAX_CANONICAL_CLUSTER_VARIANTS {
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
            interleave_pre_fold_groups(groups, positions, current, results)?;
            positions[group_index] -= 1;
            current.pop();
        }
    }
    Some(())
}

fn append_folded_sequence(
    graph: &mut NameGraph,
    start: usize,
    end: usize,
    units: &[NameUnit],
) -> Option<()> {
    let mut clusters = Vec::new();
    let mut cluster = Vec::new();
    for unit in units {
        if canonical_combining_class(unit.ch) == 0 && !cluster.is_empty() {
            clusters.push(std::mem::take(&mut cluster));
        }
        cluster.push(unit.clone());
    }
    if !cluster.is_empty() {
        clusters.push(cluster);
    }
    let mut current = start;
    let cluster_count = clusters.len();
    for (index, cluster) in clusters.into_iter().enumerate() {
        let target = if index + 1 == cluster_count {
            end
        } else {
            add_graph_node(graph)?
        };
        append_canonical_cluster(graph, current, target, &cluster)?;
        current = target;
    }
    Some(())
}

fn append_canonical_cluster(
    graph: &mut NameGraph,
    start: usize,
    end: usize,
    cluster: &[NameUnit],
) -> Option<()> {
    let cluster_variants = canonical_cluster_variants(cluster)?;
    for variant in cluster_variants {
        let mut node = start;
        let mut units = variant.into_iter().peekable();
        while let Some(unit) = units.next() {
            let target = if units.peek().is_none() {
                end
            } else if let Some(target) = graph.edges[node]
                .iter()
                .find_map(|edge| (edge.unit == unit && edge.target != end).then_some(edge.target))
            {
                target
            } else {
                let target = add_graph_node(graph)?;
                add_graph_edge(
                    graph,
                    node,
                    NameEdge {
                        unit: unit.clone(),
                        target,
                    },
                )?;
                target
            };
            if units.peek().is_none()
                && !graph.edges[node]
                    .iter()
                    .any(|edge| edge.unit == unit && edge.target == target)
            {
                add_graph_edge(graph, node, NameEdge { unit, target })?;
            }
            node = target;
        }
    }
    Some(())
}

fn add_graph_node(graph: &mut NameGraph) -> Option<usize> {
    if graph.edges.len() >= MAX_NAME_GRAPH_ITEMS {
        return None;
    }
    let node = graph.edges.len();
    graph.edges.push(Vec::new());
    graph.cluster_boundaries.push(false);
    Some(node)
}

fn add_graph_edge(graph: &mut NameGraph, from: usize, edge: NameEdge) -> Option<()> {
    if graph.edge_count >= MAX_NAME_GRAPH_ITEMS {
        return None;
    }
    graph.edges[from].push(edge);
    graph.edge_count += 1;
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
        if results.len() == MAX_CANONICAL_CLUSTER_VARIANTS {
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
    positions: Vec<u16>,
    component_start: bool,
    pending_stars: u8,
    pending_literal: String,
    used_wildcard: bool,
}

const UNREACHABLE: u16 = u16::MAX;
const NO_LITERAL_RANK: u16 = 0;

fn match_tokens(tokens: &[GlobToken], graph: &NameGraph, require_wildcard: bool) -> Option<bool> {
    let mut positions = vec![UNREACHABLE; graph.edges.len()];
    positions[0] = NO_LITERAL_RANK;
    let states = advance_sequence(
        tokens,
        vec![MatchState {
            positions,
            component_start: true,
            pending_stars: 0,
            pending_literal: String::new(),
            used_wildcard: false,
        }],
        graph,
    )?;
    Some(finish_states(states, graph)?.iter().any(|state| {
        state.positions[graph.end] != UNREACHABLE && (!require_wildcard || state.used_wildcard)
    }))
}

fn advance_sequence(
    tokens: &[GlobToken],
    mut states: Vec<MatchState>,
    graph: &NameGraph,
) -> Option<Vec<MatchState>> {
    for token in tokens {
        states = match token {
            GlobToken::Literal(literal) => advance_literal(literal, states, graph)?,
            GlobToken::Star | GlobToken::DoubleStar => {
                let count = if matches!(token, GlobToken::DoubleStar) {
                    2
                } else {
                    1
                };
                let mut states = flush_pending_literals(states, graph)?;
                for state in &mut states {
                    state.used_wildcard = true;
                    reset_literal_ranks(&mut state.positions);
                    state.pending_stars = state.pending_stars.saturating_add(count).min(2);
                }
                states
            }
            GlobToken::Alternatives(alternatives) => {
                let mut branches = Vec::new();
                for state in states {
                    for alternative in alternatives {
                        branches.extend(advance_sequence(alternative, vec![state.clone()], graph)?);
                        branches = merge_states(branches)?;
                    }
                }
                branches
            }
            _ => advance_nonstar(token, states, graph)?,
        };
    }
    Some(states)
}

fn advance_nonstar(
    token: &GlobToken,
    states: Vec<MatchState>,
    graph: &NameGraph,
) -> Option<Vec<MatchState>> {
    let mut advanced = Vec::new();
    let mut states = states;
    if matches!(token, GlobToken::Any | GlobToken::Class { .. }) {
        for state in &mut states {
            state.used_wildcard = true;
        }
    }
    for mut state in flush_pending_literals(states, graph)? {
        if matches!(token, GlobToken::Any | GlobToken::Class { .. }) {
            reset_literal_ranks(&mut state.positions);
            state.component_start = false;
        }
        if state.pending_stars >= 2
            && state.component_start
            && matches!(token, GlobToken::Separator)
        {
            state.positions = globstar_directory_positions(&state.positions, graph);
            state.pending_stars = 0;
            state.component_start = true;
            advanced.push(state);
            continue;
        }
        if state.pending_stars > 0 {
            state.positions = star_positions(&state.positions, graph, false);
            state.pending_stars = 0;
        }
        state.positions = token_positions(token, &state.positions, graph);
        state.component_start = matches!(token, GlobToken::Separator);
        advanced.push(state);
    }
    merge_states(advanced)
}

fn finish_states(states: Vec<MatchState>, graph: &NameGraph) -> Option<Vec<MatchState>> {
    let mut finished = Vec::new();
    for mut state in flush_pending_literals(states, graph)? {
        if state.pending_stars > 0 {
            let crosses_separators = state.pending_stars >= 2 && state.component_start;
            state.positions = star_positions(&state.positions, graph, crosses_separators);
            state.pending_stars = 0;
        }
        finished.push(state);
    }
    merge_states(finished)
}

fn merge_states(states: Vec<MatchState>) -> Option<Vec<MatchState>> {
    let mut merged: Vec<MatchState> = Vec::new();
    for state in states {
        if !state
            .positions
            .iter()
            .any(|position| *position != UNREACHABLE)
        {
            continue;
        }
        if let Some(existing) = merged.iter_mut().find(|existing| {
            existing.component_start == state.component_start
                && existing.pending_stars == state.pending_stars
                && existing.pending_literal == state.pending_literal
                && existing.used_wildcard == state.used_wildcard
        }) {
            for (target, source) in existing.positions.iter_mut().zip(state.positions) {
                *target = (*target).min(source);
            }
        } else {
            if merged.len() == MAX_MATCH_STATES {
                return None;
            }
            merged.push(state);
        }
    }
    Some(merged)
}

fn advance_literal(
    literal: &str,
    states: Vec<MatchState>,
    graph: &NameGraph,
) -> Option<Vec<MatchState>> {
    let mut advanced = Vec::new();
    for mut state in states {
        if state.pending_stars > 0 {
            state.positions = star_positions(&state.positions, graph, false);
            state.pending_stars = 0;
        }
        for ch in literal.nfd() {
            if canonical_combining_class(ch) == 0 && !state.pending_literal.is_empty() {
                flush_pending_literal(&mut state, graph);
            }
            if canonical_combining_class(ch) == 0 {
                consume_literal_starter(&mut state, ch, graph);
            } else {
                state.pending_literal.push(ch);
            }
        }
        advanced.push(state);
    }
    advanced.retain(|state| pending_cluster_can_continue(state, graph));
    merge_states(advanced)
}

fn pending_cluster_can_continue(state: &MatchState, graph: &NameGraph) -> bool {
    if state.pending_literal.is_empty() {
        return true;
    }
    let mut required: Vec<(u8, Vec<char>)> = Vec::new();
    for ch in fold_for_glob(&state.pending_literal).chars() {
        let class = canonical_combining_class(ch);
        if let Some((_, chars)) = required
            .iter_mut()
            .find(|(candidate, _)| *candidate == class)
        {
            chars.push(ch);
        } else {
            required.push((class, vec![ch]));
        }
    }
    let has_folded_starter = required
        .iter()
        .any(|(class, chars)| *class == 0 && !chars.is_empty());
    state.positions.iter().enumerate().any(|(node, rank)| {
        *rank != UNREACHABLE
            && (!graph.cluster_boundaries[node] || state.component_start || has_folded_starter)
            && cluster_path_contains_units(node, &required, graph)
    })
}

fn cluster_path_contains_units(
    node: usize,
    required: &[(u8, Vec<char>)],
    graph: &NameGraph,
) -> bool {
    let progress = vec![0; required.len()];
    let mut stack = vec![(node, progress.clone())];
    let mut seen = HashSet::from([(node, progress)]);
    while let Some((node, progress)) = stack.pop() {
        for edge in &graph.edges[node] {
            let class = canonical_combining_class(edge.unit.ch);
            let mut successors = vec![progress.clone()];
            if let Some(index) = required.iter().enumerate().find_map(|(index, group)| {
                (group.0 == class
                    && group
                        .1
                        .get(progress[index])
                        .is_some_and(|ch| *ch == edge.unit.ch))
                .then_some(index)
            }) {
                let mut consumed = progress.clone();
                consumed[index] += 1;
                successors.push(consumed);
            }
            for successor in successors {
                if required
                    .iter()
                    .zip(&successor)
                    .all(|((_, chars), position)| *position == chars.len())
                {
                    return true;
                }
                let has_folded_starter = required
                    .iter()
                    .zip(&successor)
                    .any(|((class, chars), position)| *class == 0 && *position < chars.len());
                if graph.cluster_boundaries[edge.target] && !has_folded_starter {
                    continue;
                }
                let next = (edge.target, successor.clone());
                if seen.contains(&next) {
                    continue;
                }
                if seen.len() == MAX_PENDING_PROBE_STATES {
                    // This probe is only an optimization. Keeping the state lets
                    // the bounded matcher decide safely without unbounded work.
                    return true;
                }
                seen.insert(next);
                stack.push((edge.target, successor));
            }
        }
    }
    false
}

fn flush_pending_literals(states: Vec<MatchState>, graph: &NameGraph) -> Option<Vec<MatchState>> {
    let mut flushed = Vec::new();
    for mut state in states {
        flush_pending_literal(&mut state, graph);
        flushed.push(state);
    }
    merge_states(flushed)
}

fn consume_literal_starter(state: &mut MatchState, starter: char, graph: &NameGraph) {
    let folded = fold_for_glob(&starter.to_string());
    let split = folded
        .char_indices()
        .find_map(|(index, ch)| (canonical_combining_class(ch) != 0).then_some(index))
        .unwrap_or(folded.len());
    if split > 0 {
        state.positions = literal_positions(&folded[..split], &state.positions, graph);
        state.component_start = false;
    }
    state.pending_literal.push_str(&folded[split..]);
}

fn flush_pending_literal(state: &mut MatchState, graph: &NameGraph) {
    if state.pending_literal.is_empty() {
        return;
    }
    let expected = fold_for_glob(&state.pending_literal);
    state.positions = literal_positions(&expected, &state.positions, graph);
    state.pending_literal.clear();
    state.component_start = false;
}

fn reset_literal_ranks(positions: &mut [u16]) {
    for rank in positions {
        if *rank != UNREACHABLE {
            *rank = NO_LITERAL_RANK;
        }
    }
}

fn step_literal(rank: u16, edge: &NameEdge, graph: &NameGraph) -> u16 {
    step_literal_unit(rank, &edge.unit, edge.target, graph)
}

fn step_literal_unit(rank: u16, unit: &NameUnit, target: usize, graph: &NameGraph) -> u16 {
    let edge_rank = unit.canonical_rank.saturating_add(1);
    if rank != NO_LITERAL_RANK && edge_rank < rank {
        return UNREACHABLE;
    }
    if graph.cluster_boundaries[target] {
        NO_LITERAL_RANK
    } else {
        edge_rank
    }
}

fn step_wildcard(rank: u16, target: usize, graph: &NameGraph) -> u16 {
    if graph.cluster_boundaries[target] {
        NO_LITERAL_RANK
    } else {
        rank
    }
}

fn advance_wildcard_path(mut rank: u16, steps: &[usize], graph: &NameGraph) -> u16 {
    for target in steps {
        rank = step_wildcard(rank, *target, graph);
    }
    rank
}

fn class_path_is_canonical(path: &CharacterPath, graph: &NameGraph) -> bool {
    let mut rank = NO_LITERAL_RANK;
    for (unit, target) in path.units.iter().zip(&path.steps) {
        rank = step_literal_unit(rank, unit, *target, graph);
        if rank == UNREACHABLE {
            return false;
        }
    }
    true
}

fn literal_positions(expected: &str, positions: &[u16], graph: &NameGraph) -> Vec<u16> {
    let mut next = vec![UNREACHABLE; graph.edges.len()];
    for (start, rank) in positions.iter().copied().enumerate() {
        if rank != UNREACHABLE {
            for (end, rank) in consume_literal(expected, graph, start, rank) {
                next[end] = next[end].min(rank);
            }
        }
    }
    next
}

fn token_positions(token: &GlobToken, positions: &[u16], graph: &NameGraph) -> Vec<u16> {
    let mut next = vec![UNREACHABLE; graph.edges.len()];
    for (start, rank) in positions.iter().copied().enumerate() {
        if rank == UNREACHABLE || start == graph.end {
            continue;
        }
        match token {
            GlobToken::Literal(_) => unreachable!("literal fragments are buffered before matching"),
            GlobToken::Separator => {
                for edge in &graph.edges[start] {
                    if edge.unit.separator {
                        next[edge.target] = next[edge.target].min(step_literal(rank, edge, graph));
                    }
                }
            }
            GlobToken::Any => {
                for path in equivalent_character_paths(graph, start) {
                    if class_path_is_canonical(&path, graph) {
                        next[path.end] =
                            next[path.end].min(advance_wildcard_path(rank, &path.steps, graph));
                    }
                }
            }
            GlobToken::Class { negated, ranges } => {
                for (end, path_provenance) in class_match_ends(*negated, ranges, graph, start, rank)
                {
                    next[end] = next[end].min(path_provenance);
                }
            }
            GlobToken::Star | GlobToken::DoubleStar | GlobToken::Alternatives(_) => {
                unreachable!("handled before primitive token matching")
            }
        }
    }
    next
}

fn star_positions(positions: &[u16], graph: &NameGraph, crosses_separators: bool) -> Vec<u16> {
    let mut next = positions.to_vec();
    let mut stack: Vec<usize> = positions
        .iter()
        .enumerate()
        .filter_map(|(node, rank)| (*rank != UNREACHABLE).then_some(node))
        .collect();
    while let Some(node) = stack.pop() {
        for edge in &graph.edges[node] {
            if crosses_separators || !edge.unit.separator {
                let rank = step_wildcard(next[node], edge.target, graph);
                if rank < next[edge.target] {
                    next[edge.target] = rank;
                    stack.push(edge.target);
                }
            }
        }
    }
    next
}

fn globstar_directory_positions(positions: &[u16], graph: &NameGraph) -> Vec<u16> {
    let mut next = positions.to_vec();
    let mut reachable = positions.to_vec();
    let mut stack: Vec<usize> = positions
        .iter()
        .enumerate()
        .filter_map(|(node, rank)| (*rank != UNREACHABLE).then_some(node))
        .collect();
    while let Some(node) = stack.pop() {
        for edge in &graph.edges[node] {
            let rank = step_wildcard(reachable[node], edge.target, graph);
            if rank < reachable[edge.target] {
                reachable[edge.target] = rank;
                stack.push(edge.target);
            }
            if edge.unit.separator {
                next[edge.target] = next[edge.target].min(rank);
            }
        }
    }
    next
}

fn consume_literal(
    expected: &str,
    graph: &NameGraph,
    start: usize,
    rank: u16,
) -> Vec<(usize, u16)> {
    let expected: Vec<char> = expected.chars().collect();
    let mut ends: Vec<(usize, u16)> = Vec::new();
    let mut stack = vec![(start, 0, rank)];
    while let Some((node, offset, rank)) = stack.pop() {
        if offset == expected.len() {
            if let Some((_, existing)) = ends.iter_mut().find(|(end, _)| *end == node) {
                *existing = (*existing).min(rank);
            } else {
                ends.push((node, rank));
            }
            continue;
        }
        for edge in &graph.edges[node] {
            if !edge.unit.separator && edge.unit.ch == expected[offset] {
                let rank = step_literal(rank, edge, graph);
                if rank != UNREACHABLE {
                    stack.push((edge.target, offset + 1, rank));
                }
            }
        }
    }
    ends
}

#[derive(Clone)]
struct CharacterPath {
    end: usize,
    units: Vec<NameUnit>,
    steps: Vec<usize>,
}

fn equivalent_character_paths(graph: &NameGraph, start: usize) -> Vec<CharacterPath> {
    let mut ends = Vec::new();
    let mut stack = vec![(start, Vec::new(), Vec::new())];
    while let Some((node, path, steps)) = stack.pop() {
        for edge in &graph.edges[node] {
            if edge.unit.separator {
                continue;
            }
            let mut path = path.clone();
            path.push(edge.unit.clone());
            let mut steps = steps.clone();
            steps.push(edge.target);
            let (endpoint, keep_scanning) = character_path_status(&path);
            if endpoint {
                ends.push(CharacterPath {
                    end: edge.target,
                    units: path.clone(),
                    steps: steps.clone(),
                });
            }
            if keep_scanning {
                stack.push((edge.target, path, steps));
            }
        }
    }
    ends
}

fn character_path_status(path: &[NameUnit]) -> (bool, bool) {
    let text: String = path.iter().map(|unit| unit.ch).collect();
    let mut composed = text.nfc();
    let endpoint = (composed.next().is_some() && composed.next().is_none())
        || original_scalar(path, 0, path.len()).is_some()
        || pre_fold_scalar(path, 0, path.len()).is_some();
    let last = path.last().unwrap();
    let reached_new_starter = path.len() > 1
        && canonical_combining_class(last.ch) == 0
        && !incomplete_source_scalar(path, 0, path.len())
        && !incomplete_pre_fold_unit(path, 0, path.len());
    (endpoint, endpoint || !reached_new_starter)
}

fn class_match_ends(
    negated: bool,
    ranges: &[(char, char)],
    graph: &NameGraph,
    start: usize,
    rank: u16,
) -> Vec<(usize, u16)> {
    equivalent_character_paths(graph, start)
        .into_iter()
        .filter_map(|path| {
            if !class_path_is_canonical(&path, graph) {
                return None;
            }
            let text: String = path.units.iter().map(|unit| unit.ch).collect();
            let mut candidates = equivalent_class_chars(&text);
            if let Some(original) = original_scalar(&path.units, 0, path.units.len()) {
                for candidate in equivalent_class_chars(&original.to_string()) {
                    if !candidates.contains(&candidate) {
                        candidates.push(candidate);
                    }
                }
            }
            if let Some(pre_fold) = pre_fold_scalar(&path.units, 0, path.units.len()) {
                for candidate in equivalent_class_chars(&pre_fold.to_string()) {
                    if !candidates.contains(&candidate) {
                        candidates.push(candidate);
                    }
                }
            }
            candidates
                .into_iter()
                .any(|candidate| {
                    let contained = ranges
                        .iter()
                        .any(|(low, high)| *low <= candidate && candidate <= *high);
                    contained != negated
                })
                .then(|| (path.end, advance_wildcard_path(rank, &path.steps, graph)))
                .filter(|(_, rank)| *rank != UNREACHABLE)
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
        assert!(!glob_matches_folded(
            "\u{3b1}\u{3af}.txt",
            "\u{3b1}\u{345}\u{301}.TXT"
        ));
        assert!(!glob_matches_folded(
            "{\u{3b1}\u{3af},x}.txt",
            "\u{3b1}\u{345}\u{301}.TXT"
        ));
        assert!(!glob_matches_folded(
            "{\u{3b1}\u{3af},x*}.txt",
            "\u{3b1}\u{345}\u{301}.TXT"
        ));
        assert!(!glob_matches_folded(
            "*/\u{3b1}\u{3af}.txt",
            "dir/\u{3b1}\u{345}\u{301}.TXT"
        ));
        assert!(!glob_matches_folded(
            "\u{3b1}\u{3af}-*.txt",
            "\u{3b1}\u{345}\u{301}-note.TXT"
        ));
        assert!(!glob_matches_folded(
            "*x\u{3b1}\u{3af}.txt",
            "x\u{3b1}\u{345}\u{301}.TXT"
        ));
        assert!(glob_matches_folded(
            "\u{3b1}\u{345}*\u{3b9}.txt",
            "\u{3b1}\u{345}\u{301}\u{345}.TXT"
        ));
        assert!(!glob_matches_folded(
            "*\u{3af}*.txt",
            "\u{3b1}\u{345}\u{301}.TXT"
        ));
        assert!(!glob_matches_folded(
            "\u{3b1}\u{3af}*.txt",
            "\u{3b1}\u{345}\u{301}\u{327}.TXT"
        ));
        assert!(!glob_matches_folded(
            "*\u{3af}.txt",
            "\u{3b1}\u{327}\u{301}\u{345}\u{301}.TXT"
        ));
        assert!(glob_matches_folded(
            "\u{3b1}\u{345}*\u{301}.txt",
            "\u{3b1}\u{301}\u{345}.TXT"
        ));
        assert!(glob_matches_folded(
            "\u{e1}*.txt/foo",
            "a\u{327}\u{301}.TXT/FOO"
        ));
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
        assert!(glob_matches_folded("[\u{130}]*.txt", "I\u{327}\u{307}.TXT"));
        assert!(!glob_matches_folded(
            "\u{3b1}[\u{3af}].txt",
            "\u{3b1}\u{345}\u{301}.TXT"
        ));
        assert!(!glob_matches_folded(
            "*[\u{3af}]*.txt",
            "\u{3b1}\u{345}\u{301}.TXT"
        ));
        assert!(!glob_matches_folded(
            "\u{3b1}?.txt",
            "\u{3b1}\u{345}\u{301}.TXT"
        ));
        assert!(glob_matches_folded(
            "\u{3b1}[\u{3b9}]\u{301}.txt",
            "\u{3b1}\u{345}\u{301}.TXT"
        ));
        assert!(glob_matches_folded(
            "\u{3b1}\u{345}*.txt",
            "\u{3b1}\u{3b9}.TXT"
        ));
        assert!(glob_matches_folded(
            "\u{3b1}\u{345}*.txt",
            "\u{3b1}\u{301}\u{3b9}.TXT"
        ));
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
        assert!(glob_matches_folded(
            "\u{3b1}{\u{345},x}\u{301}.txt",
            "\u{3b1}\u{345}\u{301}.TXT"
        ));
        assert!(glob_matches_folded(
            "\u{3b1}\u{345}*.txt",
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
        assert!(!glob_matches_folded(
            "*.exe",
            &format!("{}.txt", "\u{1ead}".repeat(9))
        ));
        let shared_cluster = format!("a{}{}.txt", "\u{301}".repeat(5), "\u{327}".repeat(5));
        assert!(!glob_matches_folded("*.exe", &shared_cluster));
        let combining_braces = format!("a{}.txt", "{\u{301},\u{300}}".repeat(20));
        assert!(!glob_matches_folded(&combining_braces, "unrelated.rs"));
        let unreachable_combining_braces = format!("a{}.txt", "{\u{301},\u{300}}".repeat(11));
        assert!(!glob_matches_folded(&unreachable_combining_braces, "a.txt"));
        let ordered_combining_name =
            format!("a{}{}.TXT", "\u{301}".repeat(11), "\u{300}".repeat(11));
        let ordered_combining_braces = format!("a{}.exe", "{\u{301},\u{300}}".repeat(11));
        assert!(!glob_matches_folded(
            &ordered_combining_braces,
            &ordered_combining_name
        ));
        let long_pending_probe = format!("\u{3b1}{}.TXT", "a".repeat(60_000));
        assert!(!glob_matches_folded(
            "\u{3b1}\u{345}*.txt",
            &long_pending_probe
        ));
        let branching_pending_probe = format!("\u{3b1}{}.TXT", "a\u{301}\u{327}".repeat(16));
        assert!(!glob_matches_folded(
            "\u{3b1}\u{345}*.txt",
            &branching_pending_probe
        ));
        let duplicate_braces = format!("{{{}}}.txt", vec!["a"; 1_025].join(","));
        assert!(!glob_matches_folded(&duplicate_braces, "another.rs"));
    }

    #[test]
    fn canonical_variant_generation_is_bounded_and_linear_for_simple_names() {
        let long_ascii_name = "a".repeat(65_535);
        let graph = canonical_name_graph(&long_ascii_name).unwrap();
        assert_eq!(graph.end, long_ascii_name.len());

        let too_many_marks = format!("a{}", "\u{301}".repeat(MAX_COMBINING_MARKS_PER_CLUSTER + 1));
        assert!(canonical_name_graph(&too_many_marks).is_none());

        let expensive_if_folded = format!("{}{}", "a\u{327}\u{301}".repeat(8), "z".repeat(60_000));
        assert!(glob_matches_folded("*", &expensive_if_folded));

        let too_many_graph_nodes =
            "a\u{301}\u{301}\u{301}\u{301}\u{301}\u{327}\u{327}\u{327}\u{327}\u{327}".repeat(3_000);
        assert!(canonical_name_graph(&too_many_graph_nodes).is_none());
    }

    #[test]
    fn equivalence_limits_are_checked_before_matching() {
        let too_many_marks = format!(
            "a{}.TXT",
            "\u{301}".repeat(MAX_COMBINING_MARKS_PER_CLUSTER + 1)
        );
        assert_eq!(
            equivalent_glob_match("?.txt", &too_many_marks),
            EquivalentMatch::Indeterminate
        );

        let oversized = "a".repeat(MAX_NAME_GRAPH_ITEMS);
        assert_eq!(
            equivalent_glob_match("*.txt", &oversized),
            EquivalentMatch::Indeterminate
        );
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
