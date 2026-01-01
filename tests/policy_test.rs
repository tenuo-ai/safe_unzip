//! Unit tests for individual policy implementations

use safe_unzip::entry::EntryKind;
use safe_unzip::policy::{
    CountPolicy, DepthPolicy, PathPolicy, Policy, PolicyChain, PolicyConfig, SizePolicy,
    SymlinkBehavior, SymlinkPolicy,
};
use safe_unzip::Error;
use tempfile::tempdir;

/// Helper to create an EntryInfo (the runtime entry type policies use)
fn make_entry_info(name: &str, size: u64, kind: EntryKind) -> safe_unzip::entry::EntryInfo {
    safe_unzip::entry::EntryInfo {
        name: name.to_string(),
        size,
        kind,
        mode: Some(0o644),
    }
}

fn file_info(name: &str, size: u64) -> safe_unzip::entry::EntryInfo {
    make_entry_info(name, size, EntryKind::File)
}

fn dir_info(name: &str) -> safe_unzip::entry::EntryInfo {
    make_entry_info(name, 0, EntryKind::Directory)
}

fn symlink_info(name: &str, target: &str) -> safe_unzip::entry::EntryInfo {
    make_entry_info(
        name,
        0,
        EntryKind::Symlink {
            target: target.to_string(),
        },
    )
}

fn default_state() -> safe_unzip::policy::ExtractionState {
    safe_unzip::policy::ExtractionState::default()
}

// ============================================================================
// PathPolicy Tests
// ============================================================================

#[test]
fn test_path_policy_normal_file() {
    let dest = tempdir().unwrap();
    let policy = PathPolicy::new(dest.path()).unwrap();
    let state = default_state();

    let entry = file_info("normal.txt", 100);
    assert!(policy.check(&entry, &state).is_ok());
}

#[test]
fn test_path_policy_blocks_traversal() {
    let dest = tempdir().unwrap();
    let policy = PathPolicy::new(dest.path()).unwrap();
    let state = default_state();

    let entry = file_info("../escape.txt", 100);
    let result = policy.check(&entry, &state);
    assert!(matches!(result, Err(Error::PathEscape { .. })));
}

#[test]
fn test_path_policy_blocks_double_dot() {
    let dest = tempdir().unwrap();
    let policy = PathPolicy::new(dest.path()).unwrap();
    let state = default_state();

    let entry = file_info("foo/../../bar.txt", 100);
    let result = policy.check(&entry, &state);
    assert!(matches!(result, Err(Error::PathEscape { .. })));
}

#[test]
fn test_path_policy_blocks_backslash() {
    let dest = tempdir().unwrap();
    let policy = PathPolicy::new(dest.path()).unwrap();
    let state = default_state();

    let entry = file_info("folder\\file.txt", 100);
    let result = policy.check(&entry, &state);
    assert!(matches!(result, Err(Error::InvalidFilename { .. })));
}

#[test]
fn test_path_policy_blocks_empty_name() {
    let dest = tempdir().unwrap();
    let policy = PathPolicy::new(dest.path()).unwrap();
    let state = default_state();

    let entry = file_info("", 100);
    let result = policy.check(&entry, &state);
    assert!(result.is_err());
}

#[test]
fn test_path_policy_blocks_control_chars() {
    let dest = tempdir().unwrap();
    let policy = PathPolicy::new(dest.path()).unwrap();
    let state = default_state();

    let entry = file_info("file\x00.txt", 100);
    let result = policy.check(&entry, &state);
    assert!(matches!(result, Err(Error::InvalidFilename { .. })));
}

// ============================================================================
// SizePolicy Tests
// ============================================================================

#[test]
fn test_size_policy_allows_small_file() {
    let policy = SizePolicy::new(1000, 10000);
    let state = default_state();

    let entry = file_info("small.txt", 500);
    assert!(policy.check(&entry, &state).is_ok());
}

#[test]
fn test_size_policy_blocks_large_file() {
    let policy = SizePolicy::new(100, 10000);
    let state = default_state();

    let entry = file_info("large.txt", 500);
    let result = policy.check(&entry, &state);
    assert!(matches!(result, Err(Error::FileTooLarge { .. })));
}

#[test]
fn test_size_policy_blocks_total_exceeded() {
    let policy = SizePolicy::new(1000, 500);
    let mut state = default_state();
    state.bytes_written = 400;

    let entry = file_info("file.txt", 200);
    let result = policy.check(&entry, &state);
    assert!(matches!(result, Err(Error::TotalSizeExceeded { .. })));
}

// ============================================================================
// CountPolicy Tests
// ============================================================================

#[test]
fn test_count_policy_allows_within_limit() {
    let policy = CountPolicy::new(10);
    let mut state = default_state();
    state.files_extracted = 5;

    let entry = file_info("file.txt", 100);
    assert!(policy.check(&entry, &state).is_ok());
}

#[test]
fn test_count_policy_blocks_at_limit() {
    let policy = CountPolicy::new(10);
    let mut state = default_state();
    state.files_extracted = 10;

    let entry = file_info("file.txt", 100);
    let result = policy.check(&entry, &state);
    assert!(matches!(result, Err(Error::FileCountExceeded { .. })));
}

#[test]
fn test_count_policy_zero_limit() {
    let policy = CountPolicy::new(0);
    let state = default_state();

    let entry = file_info("file.txt", 100);
    let result = policy.check(&entry, &state);
    assert!(matches!(result, Err(Error::FileCountExceeded { .. })));
}

// ============================================================================
// DepthPolicy Tests
// ============================================================================

#[test]
fn test_depth_policy_allows_shallow() {
    let policy = DepthPolicy::new(5);
    let state = default_state();

    let entry = file_info("a/b/file.txt", 100);
    assert!(policy.check(&entry, &state).is_ok());
}

#[test]
fn test_depth_policy_blocks_deep() {
    let policy = DepthPolicy::new(3);
    let state = default_state();

    let entry = file_info("a/b/c/d/file.txt", 100);
    let result = policy.check(&entry, &state);
    assert!(matches!(result, Err(Error::PathTooDeep { .. })));
}

// ============================================================================
// SymlinkPolicy Tests
// ============================================================================

#[test]
fn test_symlink_policy_skip_allows_files() {
    let policy = SymlinkPolicy::new(SymlinkBehavior::Skip);
    let state = default_state();

    let entry = file_info("file.txt", 100);
    assert!(policy.check(&entry, &state).is_ok());
}

#[test]
fn test_symlink_policy_skip_allows_symlinks() {
    let policy = SymlinkPolicy::new(SymlinkBehavior::Skip);
    let state = default_state();

    // Skip means validation passes (skipping happens at extraction level)
    let entry = symlink_info("link", "/etc/passwd");
    assert!(policy.check(&entry, &state).is_ok());
}

#[test]
fn test_symlink_policy_error_blocks_symlinks() {
    let policy = SymlinkPolicy::new(SymlinkBehavior::Error);
    let state = default_state();

    let entry = symlink_info("link", "/etc/passwd");
    let result = policy.check(&entry, &state);
    assert!(matches!(result, Err(Error::SymlinkNotAllowed { .. })));
}

#[test]
fn test_symlink_policy_error_allows_files() {
    let policy = SymlinkPolicy::new(SymlinkBehavior::Error);
    let state = default_state();

    let entry = file_info("file.txt", 100);
    assert!(policy.check(&entry, &state).is_ok());
}

// ============================================================================
// PolicyChain Tests
// ============================================================================

#[test]
fn test_policy_chain_empty() {
    let chain = PolicyChain::new();
    let state = default_state();

    let entry = file_info("file.txt", 100);
    assert!(chain.check_all(&entry, &state).is_ok());
}

#[test]
fn test_policy_chain_single_policy() {
    let dest = tempdir().unwrap();
    let chain = PolicyChain::new().with(PathPolicy::new(dest.path()).unwrap());
    let state = default_state();

    let entry = file_info("../escape.txt", 100);
    let result = chain.check_all(&entry, &state);
    assert!(matches!(result, Err(Error::PathEscape { .. })));
}

#[test]
fn test_policy_chain_multiple_policies() {
    let dest = tempdir().unwrap();
    let chain = PolicyChain::new()
        .with(PathPolicy::new(dest.path()).unwrap())
        .with(SizePolicy::new(100, 1000))
        .with(CountPolicy::new(10));
    let state = default_state();

    // Valid entry passes all
    let entry = file_info("small.txt", 50);
    assert!(chain.check_all(&entry, &state).is_ok());

    // Large file fails size policy
    let entry = file_info("large.txt", 500);
    let result = chain.check_all(&entry, &state);
    assert!(matches!(result, Err(Error::FileTooLarge { .. })));

    // Traversal fails path policy
    let entry = file_info("../escape.txt", 50);
    let result = chain.check_all(&entry, &state);
    assert!(matches!(result, Err(Error::PathEscape { .. })));
}

// ============================================================================
// PolicyConfig Tests
// ============================================================================

#[test]
fn test_policy_config_build() {
    let dest = tempdir().unwrap();
    let config = PolicyConfig {
        destination: dest.path().to_path_buf(),
        max_single_file: 1000,
        max_total: 10000,
        max_files: 100,
        max_depth: 10,
        symlink_behavior: SymlinkBehavior::Skip,
    };

    let chain = config.build().unwrap();
    let state = default_state();

    // Valid entry passes
    let entry = file_info("test.txt", 500);
    assert!(chain.check_all(&entry, &state).is_ok());

    // Large file fails
    let entry = file_info("big.txt", 5000);
    let result = chain.check_all(&entry, &state);
    assert!(matches!(result, Err(Error::FileTooLarge { .. })));
}

#[test]
fn test_policy_config_symlink_error() {
    let dest = tempdir().unwrap();
    let config = PolicyConfig {
        destination: dest.path().to_path_buf(),
        max_single_file: 1000,
        max_total: 10000,
        max_files: 100,
        max_depth: 10,
        symlink_behavior: SymlinkBehavior::Error,
    };

    let chain = config.build().unwrap();
    let state = default_state();

    let entry = symlink_info("link", "/etc/passwd");
    let result = chain.check_all(&entry, &state);
    assert!(matches!(result, Err(Error::SymlinkNotAllowed { .. })));
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_directory_entry_validation() {
    let dest = tempdir().unwrap();
    let chain = PolicyChain::new()
        .with(PathPolicy::new(dest.path()).unwrap())
        .with(DepthPolicy::new(3));
    let state = default_state();

    // Shallow directory passes
    let entry = dir_info("mydir/");
    assert!(chain.check_all(&entry, &state).is_ok());

    // Deep directory fails
    let entry = dir_info("a/b/c/d/e/");
    let result = chain.check_all(&entry, &state);
    assert!(matches!(result, Err(Error::PathTooDeep { .. })));
}

#[test]
fn test_cumulative_state_tracking() {
    let policy = SizePolicy::new(1000, 500);
    let mut state = default_state();

    // First file fits
    let entry = file_info("file1.txt", 200);
    assert!(policy.check(&entry, &state).is_ok());
    state.bytes_written += 200;

    // Second file fits
    let entry = file_info("file2.txt", 200);
    assert!(policy.check(&entry, &state).is_ok());
    state.bytes_written += 200;

    // Third file would exceed total
    let entry = file_info("file3.txt", 200);
    let result = policy.check(&entry, &state);
    assert!(matches!(result, Err(Error::TotalSizeExceeded { .. })));
}
