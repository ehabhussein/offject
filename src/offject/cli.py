"""Command-line interface for offject."""

import argparse
import sys
from pathlib import Path
from typing import Optional

from offject import __version__
from offject.core.architectures import get_architecture, list_architectures
from offject.repl import REPL
from offject.scripts.loader import load_script, ScriptLoaderError
from offject.core.assembler import Assembler, AssemblerError
from offject.core.patcher import Patcher, PatcherError


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser.

    Returns:
        Configured ArgumentParser
    """
    parser = argparse.ArgumentParser(
        prog="offject",
        description="Cross-platform multi-architecture binary patching tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  offject firmware.bin                    # Open file in interactive mode
  offject -a arm_thumb firmware.bin       # Open with ARM Thumb architecture
  offject -s patch.yaml firmware.bin      # Apply patch script
  offject --list-arch                     # List supported architectures

Supported architectures:
  x86, x86_16, x64, arm, arm_thumb, arm64, mips32, mips64, ppc32, ppc64, sparc32, sparc64
""",
    )

    parser.add_argument(
        "file",
        nargs="?",
        help="Binary file to open",
    )

    parser.add_argument(
        "-a", "--arch",
        metavar="ARCH",
        default="x86",
        help="Set architecture (default: x86, or auto-detect)",
    )

    parser.add_argument(
        "-s", "--script",
        metavar="FILE",
        help="Execute patch script and exit",
    )

    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Output file (default: overwrite input)",
    )

    parser.add_argument(
        "--simple",
        action="store_true",
        help="Use simple text output (no colors)",
    )

    parser.add_argument(
        "--list-arch",
        action="store_true",
        help="List supported architectures and exit",
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"offject {__version__}",
    )

    return parser


def list_arch_and_exit() -> None:
    """Print supported architectures and exit."""
    print("Supported architectures:")
    print()
    for arch in list_architectures():
        print(f"  {arch.name:<12} - {arch.description}")
    print()
    print("Aliases:")
    print("  i386, i686, x86_32 -> x86")
    print("  amd64, x86_64      -> x64")
    print("  thumb              -> arm_thumb")
    print("  aarch64            -> arm64")
    print("  mips, mipsle       -> mips32")
    print("  ppc, powerpc       -> ppc32")
    print("  sparc              -> sparc32")
    sys.exit(0)


def run_script_mode(
    file_path: str,
    script_path: str,
    arch: str,
    output_path: Optional[str],
) -> int:
    """Run in script mode (non-interactive).

    Args:
        file_path: Input binary file
        script_path: Patch script file
        arch: Architecture name
        output_path: Output file path

    Returns:
        Exit code
    """
    # Load script
    try:
        script = load_script(script_path)
    except ScriptLoaderError as e:
        print(f"Error loading script: {e}", file=sys.stderr)
        return 1

    # Use script's architecture if specified
    arch_name = script.architecture or arch
    arch_obj = get_architecture(arch_name)
    if arch_obj is None:
        print(f"Unknown architecture: {arch_name}", file=sys.stderr)
        return 1

    # Initialize assembler and patcher
    assembler = Assembler(arch_obj)
    patcher = Patcher()

    # Open file
    try:
        patcher.open(file_path)
    except PatcherError as e:
        print(f"Error opening file: {e}", file=sys.stderr)
        return 1

    print(f"Applying {len(script.patches)} patches...")

    # Apply patches
    applied = 0
    failed = 0

    for entry in script.patches:
        try:
            if entry.asm:
                result = assembler.assemble(entry.asm, entry.offset)
                patcher.patch(entry.offset, result.data, entry.description)
            elif entry.hex:
                data = entry.get_bytes()
                if data:
                    patcher.patch(entry.offset, data, entry.description)
            applied += 1
            print(f"  [OK] 0x{entry.offset:08X}: {entry.description or entry.asm or entry.hex}")
        except (AssemblerError, PatcherError) as e:
            failed += 1
            print(f"  [FAIL] 0x{entry.offset:08X}: {e}", file=sys.stderr)

    # Save output
    out_path = output_path or file_path
    try:
        patcher.save(out_path)
        print(f"Saved to: {out_path}")
    except PatcherError as e:
        print(f"Error saving file: {e}", file=sys.stderr)
        return 1

    print(f"Done: {applied} applied, {failed} failed")
    return 0 if failed == 0 else 1


def main() -> int:
    """Main entry point.

    Returns:
        Exit code
    """
    parser = create_parser()
    args = parser.parse_args()

    # Handle --list-arch
    if args.list_arch:
        list_arch_and_exit()

    # Validate architecture
    if args.arch:
        arch = get_architecture(args.arch)
        if arch is None:
            print(f"Unknown architecture: {args.arch}", file=sys.stderr)
            print("Use --list-arch to see supported architectures", file=sys.stderr)
            return 1

    # Script mode (non-interactive)
    if args.script:
        if not args.file:
            print("Error: file argument required with --script", file=sys.stderr)
            return 1
        return run_script_mode(args.file, args.script, args.arch, args.output)

    # Interactive mode
    try:
        repl = REPL(
            file_path=args.file,
            arch=args.arch,
            simple_mode=args.simple,
        )
        repl.run()
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
