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
    linear: bool,
}

#[derive(Debug)]
struct NameGraph {
    edges: Vec<Vec<NameEdge>>,
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
const MAX_COMBINING_MARKS_PER_CLUSTER: usize = 64;
const MAX_NAME_GRAPH_ITEMS: usize = 65_536;
const MAX_MATCH_STATES: usize = 1_024;

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
    if literal_only(&tokens) {
        return EquivalentMatch::NoMatch;
    }
    let Some(graph) = canonical_name_graph(name) else {
        return EquivalentMatch::Indeterminate;
    };
    match match_tokens(&tokens, &graph, true) {
        Some(true) => EquivalentMatch::Match,
        Some(false) => EquivalentMatch::NoMatch,
        None => EquivalentMatch::Indeterminate,
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
    let chars: Vec<char> = fold_for_glob(name).chars().collect();
    let mut edges = vec![Vec::new(); chars.len() + 1];
    for (index, ch) in chars.iter().copied().enumerate() {
        edges[index].push(NameEdge {
            unit: NameUnit {
                ch,
                separator: ch == '/',
                source: index,
                source_char: ch,
                source_total: 1,
                pre_unit: index,
                pre_char: ch,
                pre_total: 1,
            },
            target: index + 1,
            linear: true,
        });
    }
    NameGraph {
        edge_count: chars.len(),
        end: chars.len(),
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
        edge_count: 0,
        end: 0,
    };
    for cluster in pre_fold_clusters(name)? {
        append_pre_fold_cluster(&mut graph, &cluster)?;
    }
    Some(graph)
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
    let start = graph.end;
    let end = add_graph_node(graph)?;
    for variant in variants {
        let linear = variant
            .iter()
            .map(|unit| unit.id)
            .eq(linear_ids.iter().copied());
        let mut folded = Vec::new();
        for unit in variant {
            let chars: Vec<char> = unit.ch.to_string().case_fold().nfd().collect();
            let pre_total = chars.len();
            let source_total = unit.source_char.to_string().nfd().case_fold().nfd().count();
            for ch in chars {
                folded.push(NameUnit {
                    ch,
                    separator: ch == '/',
                    source: unit.source,
                    source_char: unit.source_char,
                    source_total,
                    pre_unit: unit.id,
                    pre_char: unit.ch,
                    pre_total,
                });
            }
        }
        append_folded_sequence(graph, start, end, &folded, linear)?;
    }
    graph.end = end;
    Some(())
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
    linear: bool,
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
        append_canonical_cluster(graph, current, target, &cluster, linear)?;
        current = target;
    }
    Some(())
}

fn append_canonical_cluster(
    graph: &mut NameGraph,
    start: usize,
    end: usize,
    cluster: &[NameUnit],
    linear: bool,
) -> Option<()> {
    let cluster_variants = canonical_cluster_variants(cluster)?;
    let mut linear_variant = cluster.to_vec();
    let mark_start = usize::from(
        cluster
            .first()
            .is_some_and(|unit| canonical_combining_class(unit.ch) == 0),
    );
    linear_variant[mark_start..].sort_by_key(|unit| canonical_combining_class(unit.ch));
    for variant in cluster_variants {
        let variant_is_linear = linear && variant == linear_variant;
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
                        linear: variant_is_linear,
                    },
                )?;
                target
            };
            if units.peek().is_none()
                && !graph.edges[node]
                    .iter()
                    .any(|edge| edge.unit == unit && edge.target == target)
            {
                add_graph_edge(
                    graph,
                    node,
                    NameEdge {
                        unit,
                        target,
                        linear: variant_is_linear,
                    },
                )?;
            } else if variant_is_linear {
                if let Some(edge) = graph.edges[node]
                    .iter_mut()
                    .find(|edge| edge.unit == unit && edge.target == target)
                {
                    edge.linear = true;
                }
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
    positions: Vec<bool>,
    linear_positions: Vec<bool>,
    component_start: bool,
    pending_stars: u8,
    pending_literal: String,
    used_wildcard: bool,
    cluster_used_wildcard: bool,
}

fn match_tokens(tokens: &[GlobToken], graph: &NameGraph, require_wildcard: bool) -> Option<bool> {
    let mut positions = vec![false; graph.edges.len()];
    positions[0] = true;
    let states = advance_sequence(
        tokens,
        vec![MatchState {
            linear_positions: positions.clone(),
            positions,
            component_start: true,
            pending_stars: 0,
            pending_literal: String::new(),
            used_wildcard: false,
            cluster_used_wildcard: false,
        }],
        graph,
    )?;
    Some(
        finish_states(states, graph)?
            .iter()
            .any(|state| state.positions[graph.end] && (!require_wildcard || state.used_wildcard)),
    )
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
                for state in &mut states {
                    state.used_wildcard = true;
                    state.cluster_used_wildcard = true;
                }
                let mut states = flush_pending_literals(states, graph)?;
                for state in &mut states {
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
            state.cluster_used_wildcard = true;
        }
    }
    for mut state in flush_pending_literals(states, graph)? {
        if matches!(token, GlobToken::Any | GlobToken::Class { .. }) {
            state.component_start = false;
        }
        if state.pending_stars >= 2
            && state.component_start
            && matches!(token, GlobToken::Separator)
        {
            state.positions = globstar_directory_positions(&state.positions, graph);
            state.linear_positions = state.positions.clone();
            state.pending_stars = 0;
            state.component_start = true;
            state.cluster_used_wildcard = false;
            advanced.push(state);
            continue;
        }
        if state.pending_stars > 0 {
            state.positions = star_positions(&state.positions, graph, false, false);
            state.linear_positions = star_positions(&state.linear_positions, graph, false, true);
            state.pending_stars = 0;
        }
        if matches!(token, GlobToken::Separator) {
            finish_cluster(&mut state);
        }
        state.positions = token_positions(token, &state.positions, graph, false);
        if matches!(token, GlobToken::Separator) {
            state.linear_positions = state.positions.clone();
            state.cluster_used_wildcard = false;
        } else {
            state.linear_positions = token_positions(token, &state.linear_positions, graph, true);
        }
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
            state.positions = star_positions(&state.positions, graph, crosses_separators, false);
            state.linear_positions =
                star_positions(&state.linear_positions, graph, crosses_separators, true);
            state.pending_stars = 0;
        }
        finish_cluster(&mut state);
        finished.push(state);
    }
    merge_states(finished)
}

fn merge_states(states: Vec<MatchState>) -> Option<Vec<MatchState>> {
    let mut merged: Vec<MatchState> = Vec::new();
    for state in states {
        if !state.positions.iter().any(|position| *position) {
            continue;
        }
        if let Some(existing) = merged.iter_mut().find(|existing| {
            existing.component_start == state.component_start
                && existing.pending_stars == state.pending_stars
                && existing.pending_literal == state.pending_literal
                && existing.used_wildcard == state.used_wildcard
                && existing.cluster_used_wildcard == state.cluster_used_wildcard
        }) {
            for (target, source) in existing.positions.iter_mut().zip(state.positions) {
                *target |= source;
            }
            for (target, source) in existing
                .linear_positions
                .iter_mut()
                .zip(state.linear_positions)
            {
                *target |= source;
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
            state.positions = star_positions(&state.positions, graph, false, false);
            state.linear_positions = star_positions(&state.linear_positions, graph, false, true);
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
    merge_states(advanced)
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
    finish_cluster(state);
    let folded = fold_for_glob(&starter.to_string());
    let split = folded
        .char_indices()
        .find_map(|(index, ch)| (canonical_combining_class(ch) != 0).then_some(index))
        .unwrap_or(folded.len());
    if split > 0 {
        state.positions = literal_positions(&folded[..split], &state.positions, graph, false);
        state.linear_positions =
            literal_positions(&folded[..split], &state.linear_positions, graph, true);
        state.component_start = false;
    }
    state.pending_literal.push_str(&folded[split..]);
}

fn finish_cluster(state: &mut MatchState) {
    if !state.cluster_used_wildcard {
        state.positions.clone_from(&state.linear_positions);
    }
    state.linear_positions.clone_from(&state.positions);
    state.cluster_used_wildcard = false;
}

fn flush_pending_literal(state: &mut MatchState, graph: &NameGraph) {
    if state.pending_literal.is_empty() {
        return;
    }
    let expected = fold_for_glob(&state.pending_literal);
    state.positions = literal_positions(&expected, &state.positions, graph, false);
    state.linear_positions = literal_positions(&expected, &state.linear_positions, graph, true);
    state.pending_literal.clear();
    state.component_start = false;
}

fn literal_positions(
    expected: &str,
    positions: &[bool],
    graph: &NameGraph,
    linear_only: bool,
) -> Vec<bool> {
    let mut next = vec![false; graph.edges.len()];
    for (start, matched) in positions.iter().copied().enumerate() {
        if matched {
            for end in consume_literal(expected, graph, start, linear_only) {
                next[end] = true;
            }
        }
    }
    next
}

fn token_positions(
    token: &GlobToken,
    positions: &[bool],
    graph: &NameGraph,
    linear_only: bool,
) -> Vec<bool> {
    let mut next = vec![false; graph.edges.len()];
    for (start, matched) in positions.iter().copied().enumerate() {
        if !matched || start == graph.end {
            continue;
        }
        match token {
            GlobToken::Literal(_) => unreachable!("literal fragments are buffered before matching"),
            GlobToken::Separator => {
                for edge in &graph.edges[start] {
                    if edge.unit.separator && (!linear_only || edge.linear) {
                        next[edge.target] = true;
                    }
                }
            }
            GlobToken::Any => {
                for (end, _) in equivalent_character_paths(graph, start, linear_only) {
                    next[end] = true;
                }
            }
            GlobToken::Class { negated, ranges } => {
                for end in class_match_ends(*negated, ranges, graph, start, linear_only) {
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

fn star_positions(
    positions: &[bool],
    graph: &NameGraph,
    crosses_separators: bool,
    linear_only: bool,
) -> Vec<bool> {
    let mut next = positions.to_vec();
    let mut stack: Vec<usize> = positions
        .iter()
        .enumerate()
        .filter_map(|(node, reachable)| reachable.then_some(node))
        .collect();
    while let Some(node) = stack.pop() {
        for edge in &graph.edges[node] {
            if (!linear_only || edge.linear)
                && (crosses_separators || !edge.unit.separator)
                && !next[edge.target]
            {
                next[edge.target] = true;
                stack.push(edge.target);
            }
        }
    }
    next
}

fn globstar_directory_positions(positions: &[bool], graph: &NameGraph) -> Vec<bool> {
    let mut next = positions.to_vec();
    let mut reachable = positions.to_vec();
    let mut stack: Vec<usize> = positions
        .iter()
        .enumerate()
        .filter_map(|(node, reachable)| reachable.then_some(node))
        .collect();
    while let Some(node) = stack.pop() {
        for edge in &graph.edges[node] {
            if !reachable[edge.target] {
                reachable[edge.target] = true;
                stack.push(edge.target);
            }
            if edge.unit.separator {
                next[edge.target] = true;
            }
        }
    }
    next
}

fn consume_literal(
    expected: &str,
    graph: &NameGraph,
    start: usize,
    linear_only: bool,
) -> Vec<usize> {
    let expected: Vec<char> = expected.chars().collect();
    let mut ends = Vec::new();
    let mut stack = vec![(start, 0)];
    while let Some((node, offset)) = stack.pop() {
        if offset == expected.len() {
            if !ends.contains(&node) {
                ends.push(node);
            }
            continue;
        }
        for edge in &graph.edges[node] {
            if (!linear_only || edge.linear)
                && !edge.unit.separator
                && edge.unit.ch == expected[offset]
            {
                stack.push((edge.target, offset + 1));
            }
        }
    }
    ends
}

fn equivalent_character_paths(
    graph: &NameGraph,
    start: usize,
    linear_only: bool,
) -> Vec<(usize, Vec<NameUnit>)> {
    let mut ends = Vec::new();
    let mut stack = vec![(start, Vec::new())];
    while let Some((node, path)) = stack.pop() {
        for edge in &graph.edges[node] {
            if edge.unit.separator || (linear_only && !edge.linear) {
                continue;
            }
            let mut path = path.clone();
            path.push(edge.unit.clone());
            let (endpoint, keep_scanning) = character_path_status(&path);
            if endpoint {
                ends.push((edge.target, path.clone()));
            }
            if keep_scanning {
                stack.push((edge.target, path));
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
    linear_only: bool,
) -> Vec<usize> {
    equivalent_character_paths(graph, start, linear_only)
        .into_iter()
        .filter_map(|(end, path)| {
            let text: String = path.iter().map(|unit| unit.ch).collect();
            let mut candidates = equivalent_class_chars(&text);
            if let Some(original) = original_scalar(&path, 0, path.len()) {
                for candidate in equivalent_class_chars(&original.to_string()) {
                    if !candidates.contains(&candidate) {
                        candidates.push(candidate);
                    }
                }
            }
            if let Some(pre_fold) = pre_fold_scalar(&path, 0, path.len()) {
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
                .then_some(end)
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
