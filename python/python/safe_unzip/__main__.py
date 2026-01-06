"""
CLI entry point for running safe_unzip as a Python module.

Usage:
    python -m safe_unzip archive.zip -d /tmp/out
    python -m safe_unzip archive.zip --list
    python -m safe_unzip archive.zip --verify
"""

import argparse
import sys
from pathlib import Path
from typing import Optional, List

from . import (
    extract_file,
    extract_tar_file,
    extract_tar_gz_file,
    list_zip_entries,
    list_tar_entries,
    list_tar_gz_entries,
    verify_file,
    Extractor,
    SafeUnzipError,
)


def parse_size(size_str: str) -> int:
    """Parse size string like '100M', '1G' into bytes."""
    size_str = size_str.strip().upper()
    multipliers = {
        'K': 1024,
        'KB': 1024,
        'M': 1024 * 1024,
        'MB': 1024 * 1024,
        'G': 1024 * 1024 * 1024,
        'GB': 1024 * 1024 * 1024,
    }
    
    for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
        if size_str.endswith(suffix):
            num_str = size_str[:-len(suffix)]
            return int(num_str) * mult
    
    return int(size_str)


def format_bytes(num_bytes: int) -> str:
    """Format bytes as human-readable string."""
    if num_bytes >= 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024 * 1024):.1f}G"
    elif num_bytes >= 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.1f}M"
    elif num_bytes >= 1024:
        return f"{num_bytes / 1024:.1f}K"
    else:
        return f"{num_bytes}B"


def detect_format(path: Path) -> str:
    """Detect archive format from filename."""
    name = path.name.lower()
    if name.endswith('.tar.gz') or name.endswith('.tgz'):
        return 'tar.gz'
    elif name.endswith('.tar'):
        return 'tar'
    else:
        return 'zip'


def list_archive(path: Path, quiet: bool = False) -> int:
    """List archive contents."""
    fmt = detect_format(path)
    
    try:
        if fmt == 'tar.gz':
            entries = list_tar_gz_entries(path)
        elif fmt == 'tar':
            entries = list_tar_entries(path)
        else:
            entries = list_zip_entries(path)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    if not quiet:
        print(f"{len(entries)} entries in {path}:")
        print()
    
    total_size = 0
    for entry in entries:
        kind_suffix = ""
        if entry.is_dir:
            kind_suffix = "/"
        elif entry.is_symlink:
            kind_suffix = " -> [symlink]"
        
        print(f"{format_bytes(entry.size):>10}  {entry.name}{kind_suffix}")
        total_size += entry.size
    
    if not quiet:
        print()
        print(f"Total: {len(entries)} files, {format_bytes(total_size)}")
    
    return 0


def verify_archive(path: Path, quiet: bool = False) -> int:
    """Verify archive integrity."""
    if not quiet:
        print(f"Verifying {path}...")
    
    try:
        report = verify_file(path)
        if not quiet:
            print(f"✓ Verified {report.entries_verified} entries ({format_bytes(report.bytes_verified)})")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def extract_archive(
    path: Path,
    dest: Path,
    max_size: Optional[int] = None,
    max_files: Optional[int] = None,
    max_depth: Optional[int] = None,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None,
    only_files: Optional[List[str]] = None,
    overwrite: str = "error",
    symlinks: str = "skip",
    validate_first: bool = False,
    quiet: bool = False,
    verbose: bool = False,
) -> int:
    """Extract archive to destination."""
    fmt = detect_format(path)
    
    try:
        extractor = Extractor(dest)
        
        if max_size:
            extractor = extractor.max_total_bytes(max_size)
        if max_files:
            extractor = extractor.max_files(max_files)
        if max_depth:
            extractor = extractor.max_depth(max_depth)
        
        extractor = extractor.overwrite(overwrite)
        extractor = extractor.symlinks(symlinks)
        
        if validate_first:
            extractor = extractor.mode("validate_first")
        
        if only_files:
            extractor = extractor.only(only_files)
        if include_patterns:
            extractor = extractor.include_glob(include_patterns)
        if exclude_patterns:
            extractor = extractor.exclude_glob(exclude_patterns)
        
        if verbose:
            def show_progress(p):
                print(f"[{p['entry_index']+1}/{p['total_entries']}] {p['entry_name']}")
            extractor = extractor.on_progress(show_progress)
        
        if fmt == 'tar.gz':
            report = extractor.extract_tar_gz_file(path)
        elif fmt == 'tar':
            report = extractor.extract_tar_file(path)
        else:
            report = extractor.extract_file(path)
        
        if not quiet:
            print(f"Extracted {report.files_extracted} files ({format_bytes(report.bytes_written)}) to {dest}")
            if report.entries_skipped > 0:
                print(f"Skipped {report.entries_skipped} entries")
        
        return 0
        
    except SafeUnzipError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="python -m safe_unzip",
        description="Secure archive extraction - prevents Zip Slip and Zip Bombs",
    )
    
    parser.add_argument("archive", type=Path, help="Archive file to extract (ZIP, TAR, TAR.GZ)")
    parser.add_argument("-d", "--dest", type=Path, default=Path("."), help="Destination directory")
    parser.add_argument("-l", "--list", action="store_true", dest="list_contents", help="List contents without extracting")
    parser.add_argument("--verify", action="store_true", help="Verify archive integrity without extracting")
    parser.add_argument("--max-size", type=parse_size, help="Maximum total size (e.g., 100M, 1G)")
    parser.add_argument("--max-files", type=int, help="Maximum number of files")
    parser.add_argument("--max-depth", type=int, help="Maximum directory depth")
    parser.add_argument("--include", action="append", dest="include_patterns", metavar="PATTERN", help="Include files matching glob pattern")
    parser.add_argument("--exclude", action="append", dest="exclude_patterns", metavar="PATTERN", help="Exclude files matching glob pattern")
    parser.add_argument("--only", action="append", dest="only_files", metavar="FILE", help="Extract only specific files")
    parser.add_argument("--overwrite", choices=["error", "skip", "overwrite"], default="error", help="What to do if file exists")
    parser.add_argument("--symlinks", choices=["skip", "error"], default="skip", help="What to do with symlinks")
    parser.add_argument("--validate-first", action="store_true", help="Validate all entries before extracting")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    
    args = parser.parse_args()
    
    if not args.archive.exists():
        print(f"Error: archive not found: {args.archive}", file=sys.stderr)
        return 1
    
    if args.list_contents:
        return list_archive(args.archive, args.quiet)
    
    if args.verify:
        return verify_archive(args.archive, args.quiet)
    
    # Create destination if needed
    if not args.dest.exists():
        args.dest.mkdir(parents=True, exist_ok=True)
    
    return extract_archive(
        args.archive,
        args.dest,
        max_size=args.max_size,
        max_files=args.max_files,
        max_depth=args.max_depth,
        include_patterns=args.include_patterns,
        exclude_patterns=args.exclude_patterns,
        only_files=args.only_files,
        overwrite=args.overwrite,
        symlinks=args.symlinks,
        validate_first=args.validate_first,
        quiet=args.quiet,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    sys.exit(main())

