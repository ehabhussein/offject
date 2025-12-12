"""Interactive REPL for offject."""

from pathlib import Path
from typing import Optional
import shlex

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory

from offject.core.architectures import Architecture, get_architecture, list_architectures
from offject.core.assembler import Assembler, AssemblerError
from offject.core.disassembler import Disassembler
from offject.core.patcher import Patcher, PatcherError
from offject.binary.parser import BinaryFile, BinaryFormat
from offject.ui.console import Console
from offject.ui.hexview import HexView
from offject.ui.completer import OffjectCompleter, get_all_commands
from offject.scripts.loader import load_script, ScriptLoaderError
from offject.scripts.saver import save_script, create_script_from_patches
from offject.utils.helpers import parse_int


class REPL:
    """Interactive REPL for binary patching."""

    def __init__(
        self,
        file_path: Optional[str] = None,
        arch: str = "x86",
        simple_mode: bool = False,
    ):
        """Initialize REPL.

        Args:
            file_path: Optional initial file to open
            arch: Initial architecture
            simple_mode: Use simple text output
        """
        self._simple_mode = simple_mode
        self._console = Console(simple_mode=simple_mode)
        self._hexview = HexView(simple_mode=simple_mode)

        # Initialize architecture
        arch_obj = get_architecture(arch)
        if arch_obj is None:
            arch_obj = get_architecture("x86")
        self._arch = arch_obj

        # Initialize assembler and disassembler
        self._assembler = Assembler(self._arch)
        self._disassembler = Disassembler(self._arch)

        # Initialize patcher and binary parser
        self._patcher = Patcher()
        self._binary = BinaryFile()

        # State
        self._offset = 0
        self._assembled_bytes: Optional[bytes] = None
        self._running = False

        # Command completer
        self._completer = OffjectCompleter(self._arch.name)

        # Open file if provided
        if file_path:
            self._open_file(file_path)

    def _open_file(self, file_path: str) -> bool:
        """Open a file.

        Args:
            file_path: Path to file

        Returns:
            True if successful
        """
        try:
            path = Path(file_path)
            info = self._binary.open(path)
            self._patcher.open(path)
            self._offset = 0
            self._assembled_bytes = None

            # Update completer with symbols and sections
            symbols = [s.name for s in self._binary.get_symbols()]
            sections = [s.name for s in self._binary.get_sections()]
            self._completer.set_symbols(symbols)
            self._completer.set_sections(sections)

            # Auto-detect architecture if possible
            if info.architecture:
                arch_map = {
                    "x86": "x86",
                    "x86_64": "x64",
                    "ARM": "arm",
                    "ARM64": "arm64",
                    "MIPS": "mips32",
                    "PowerPC": "ppc32",
                    "PowerPC64": "ppc64",
                }
                detected_arch = arch_map.get(info.architecture)
                if detected_arch:
                    self._set_arch(detected_arch)
                    self._console.print_info(f"Auto-detected architecture: {detected_arch}")

            self._console.print_success(f"Opened: {path.name}")
            return True

        except (FileNotFoundError, PatcherError) as e:
            self._console.print_error(str(e))
            return False

    def _set_arch(self, arch_name: str) -> bool:
        """Set architecture.

        Args:
            arch_name: Architecture name

        Returns:
            True if successful
        """
        arch = get_architecture(arch_name)
        if arch is None:
            self._console.print_error(f"Unknown architecture: {arch_name}")
            return False

        self._arch = arch
        self._assembler.set_architecture(arch)
        self._disassembler.set_architecture(arch)
        self._completer.set_architecture(arch_name)
        self._assembled_bytes = None  # Clear buffer on arch change
        return True

    def run(self) -> None:
        """Run the REPL."""
        self._running = True

        # Show banner
        self._show_banner()

        # Set up prompt session
        history_path = Path.home() / ".offject_history"
        session: PromptSession = PromptSession(
            history=FileHistory(str(history_path)),
            auto_suggest=AutoSuggestFromHistory(),
            completer=self._completer,
        )

        while self._running:
            try:
                # Build prompt
                prompt = self._build_prompt()

                # Get input
                line = session.prompt(prompt)

                # Process command
                self._process_line(line)

            except KeyboardInterrupt:
                self._console.print("")
                continue
            except EOFError:
                self._running = False
                break

        self._console.print("Goodbye!")

    def _show_banner(self) -> None:
        """Show startup banner."""
        file_name = self._binary.path.name if self._binary.is_open else "<no file>"
        self._console.print_banner(
            file_name=file_name,
            arch_name=self._arch.name,
            offset=self._offset,
            modified=self._patcher.modified if self._patcher.is_open else False,
        )

    def _build_prompt(self) -> str:
        """Build the prompt string.

        Returns:
            Prompt string
        """
        modified = "*" if self._patcher.modified else ""
        return f"{modified}offject [{self._arch.name}] 0x{self._offset:X} » "

    def _process_line(self, line: str) -> None:
        """Process a command line.

        Args:
            line: Input line
        """
        line = line.strip()
        if not line:
            return

        # Parse command and arguments
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()

        if not parts:
            return

        cmd = parts[0].lower()
        args = parts[1:]

        # Dispatch command
        handlers = {
            "arch": self._cmd_arch,
            "asm": self._cmd_asm,
            "clear": self._cmd_clear,
            "disasm": self._cmd_disasm,
            "exit": self._cmd_exit,
            "goto": self._cmd_goto,
            "help": self._cmd_help,
            "hex": self._cmd_hex,
            "history": self._cmd_history,
            "info": self._cmd_info,
            "open": self._cmd_open,
            "patch": self._cmd_patch,
            "quit": self._cmd_exit,
            "redo": self._cmd_redo,
            "save": self._cmd_save,
            "script": self._cmd_script,
            "sections": self._cmd_sections,
            "symbols": self._cmd_symbols,
            "undo": self._cmd_undo,
        }

        handler = handlers.get(cmd)
        if handler:
            handler(args)
        else:
            # Try as assembly if file is open
            if self._patcher.is_open:
                self._cmd_asm([line])
            else:
                self._console.print_error(f"Unknown command: {cmd}")
                self._console.print_info("Type 'help' for available commands")

    # Command handlers

    def _cmd_arch(self, args: list[str]) -> None:
        """Handle arch command."""
        if not args:
            # Show current architecture
            self._console.print(f"Current architecture: {self._arch.name} - {self._arch.description}")
            self._console.print_architectures()
            return

        arch_name = args[0]
        if self._set_arch(arch_name):
            self._console.print_success(f"Architecture set to: {self._arch.name}")

    def _cmd_asm(self, args: list[str]) -> None:
        """Handle asm command."""
        if not args:
            if self._assembled_bytes:
                hex_str = " ".join(f"{b:02X}" for b in self._assembled_bytes)
                self._console.print(f"Buffer: {hex_str} ({len(self._assembled_bytes)} bytes)")
            else:
                self._console.print_info("No assembled bytes in buffer")
                self._console.print_info("Usage: asm [offset] <instruction(s)>")
            return

        offset = self._offset
        code_args = args

        # Check if first argument is an offset (hex or decimal number)
        if args[0].startswith("0x") or args[0].startswith("0X") or args[0].isdigit():
            try:
                offset = parse_int(args[0])
                self._offset = offset
                code_args = args[1:]
            except ValueError:
                pass  # Not a valid number, treat as code

        if not code_args:
            self._console.print_error("No assembly code provided")
            return

        code = " ".join(code_args)

        try:
            result = self._assembler.assemble(code, offset)
            self._assembled_bytes = result.data
            self._console.print_assembly_result(result.hex_spaced, result.count, len(result.data))
        except AssemblerError as e:
            self._console.print_error(str(e))

    def _cmd_clear(self, args: list[str]) -> None:
        """Handle clear command."""
        self._assembled_bytes = None
        self._console.print_info("Assembled buffer cleared")

    def _cmd_disasm(self, args: list[str]) -> None:
        """Handle disasm command."""
        if not self._patcher.is_open:
            self._console.print_error("No file is open")
            return

        offset = self._offset
        count = 10

        if len(args) >= 1:
            try:
                offset = parse_int(args[0])
                self._offset = offset
            except ValueError:
                self._console.print_error(f"Invalid offset: {args[0]}")
                return

        if len(args) >= 2:
            try:
                count = parse_int(args[1])
            except ValueError:
                self._console.print_error(f"Invalid count: {args[1]}")
                return

        # Read bytes at offset
        try:
            # Read more bytes than needed (instructions vary in size)
            data = self._patcher.read(offset, count * 16)
            instructions = self._disassembler.disassemble(data, offset, count)
            self._console.print_disassembly(instructions)
        except PatcherError as e:
            self._console.print_error(str(e))

    def _cmd_exit(self, args: list[str]) -> None:
        """Handle exit command."""
        if self._patcher.modified:
            self._console.print_warning("File has unsaved changes!")
            self._console.print_info("Use 'save' to save or 'exit' again to discard")
            # Simple confirmation - just exit on second call
            self._running = False
        else:
            self._running = False

    def _cmd_goto(self, args: list[str]) -> None:
        """Handle goto command."""
        if not args:
            self._console.print(f"Current offset: 0x{self._offset:X}")
            return

        target = args[0]

        # Try as symbol first
        if self._binary.is_open:
            symbol = self._binary.get_symbol(target)
            if symbol:
                self._offset = symbol.address
                self._console.print_success(f"Jumped to {target} @ 0x{self._offset:X}")
                return

            # Try as section
            section = self._binary.get_section(target)
            if section:
                self._offset = section.offset
                self._console.print_success(f"Jumped to section {target} @ 0x{self._offset:X}")
                return

        # Try as numeric offset
        try:
            new_offset = parse_int(target)
            if new_offset < 0:
                self._console.print_error("Offset cannot be negative")
                return
            if self._patcher.is_open and new_offset >= self._patcher.size:
                self._console.print_warning(f"Offset 0x{new_offset:X} is past end of file (0x{self._patcher.size:X})")
            self._offset = new_offset
            self._console.print_success(f"Offset: 0x{self._offset:X}")
        except ValueError:
            self._console.print_error(f"Invalid offset or unknown symbol: {target}")

    def _cmd_help(self, args: list[str]) -> None:
        """Handle help command."""
        if args:
            cmd = args[0].lower()
            help_text = self._get_detailed_help(cmd)
            if help_text:
                self._console.print(help_text)
            else:
                self._console.print_error(f"No help for: {cmd}")
            return

        self._console.print_help(get_all_commands())

    def _get_detailed_help(self, cmd: str) -> Optional[str]:
        """Get detailed help for a command."""
        help_texts = {
            "arch": "arch [name]\n  Show or set architecture\n  Examples: arch arm_thumb, arch x64",
            "asm": "asm [offset] <instruction(s)>\n  Assemble instructions at offset (default: current)\n  Also sets current offset. Separate multiple with ;\n  Example: asm 0x1000 mov eax, 0; ret",
            "disasm": "disasm [offset] [count]\n  Disassemble instructions at offset (default: current)\n  Also sets current offset. Default count: 10",
            "goto": "goto <offset|symbol>\n  Jump to offset or symbol\n  Examples: goto 0x1000, goto main",
            "hex": "hex [offset] [size]\n  Show hex dump at offset (default: current)\n  Also sets current offset. Default size: 256 bytes",
            "patch": "patch [offset]\n  Write assembled bytes at offset (default: current)\n  Also sets current offset. Must have bytes in buffer (use 'asm' first)",
            "script": "script load <file>  - Load and execute patch script\nscript save <file>  - Save patch history as script",
            "save": "save [file]\n  Save patched file\n  Without argument, saves to original file",
            "undo": "undo\n  Undo last patch",
            "redo": "redo\n  Redo last undone patch",
        }
        return help_texts.get(cmd)

    def _cmd_hex(self, args: list[str]) -> None:
        """Handle hex command."""
        if not self._patcher.is_open:
            self._console.print_error("No file is open")
            return

        offset = self._offset
        size = 256

        if len(args) >= 1:
            try:
                offset = parse_int(args[0])
                self._offset = offset
            except ValueError:
                self._console.print_error(f"Invalid offset: {args[0]}")
                return

        if len(args) >= 2:
            try:
                size = parse_int(args[1])
            except ValueError:
                self._console.print_error(f"Invalid size: {args[1]}")
                return

        try:
            data = self._patcher.read(offset, size)
            self._hexview.print(data, offset)
        except PatcherError as e:
            self._console.print_error(str(e))

    def _cmd_history(self, args: list[str]) -> None:
        """Handle history command."""
        if not self._patcher.is_open:
            self._console.print_error("No file is open")
            return

        self._console.print_history(self._patcher.history.patches)

    def _cmd_info(self, args: list[str]) -> None:
        """Handle info command."""
        if not self._binary.is_open:
            self._console.print_error("No file is open")
            return

        self._console.print_binary_info(self._binary.info)

    def _cmd_open(self, args: list[str]) -> None:
        """Handle open command."""
        if not args:
            self._console.print_error("Usage: open <file>")
            return

        file_path = " ".join(args)
        self._open_file(file_path)

    def _cmd_patch(self, args: list[str]) -> None:
        """Handle patch command."""
        if not self._patcher.is_open:
            self._console.print_error("No file is open")
            return

        if not self._assembled_bytes:
            self._console.print_error("No assembled bytes in buffer")
            self._console.print_info("Use 'asm <code>' first to assemble instructions")
            return

        offset = self._offset
        if args:
            try:
                offset = parse_int(args[0])
                self._offset = offset
            except ValueError:
                self._console.print_error(f"Invalid offset: {args[0]}")
                return

        try:
            patch = self._patcher.patch(offset, self._assembled_bytes)
            self._console.print_patch_result(patch)
            self._assembled_bytes = None  # Clear buffer after patching
        except PatcherError as e:
            self._console.print_error(str(e))

    def _cmd_redo(self, args: list[str]) -> None:
        """Handle redo command."""
        if not self._patcher.is_open:
            self._console.print_error("No file is open")
            return

        patch = self._patcher.redo()
        if patch:
            self._console.print_success(f"Redone: {patch}")
        else:
            self._console.print_info("Nothing to redo")

    def _cmd_save(self, args: list[str]) -> None:
        """Handle save command."""
        if not self._patcher.is_open:
            self._console.print_error("No file is open")
            return

        file_path = args[0] if args else None

        try:
            saved_path = self._patcher.save(file_path)
            self._console.print_success(f"Saved to: {saved_path}")
        except PatcherError as e:
            self._console.print_error(str(e))

    def _cmd_script(self, args: list[str]) -> None:
        """Handle script command."""
        if not args:
            self._console.print_info("Usage: script load <file> | script save <file>")
            return

        subcmd = args[0].lower()

        if subcmd == "load":
            if len(args) < 2:
                self._console.print_error("Usage: script load <file>")
                return
            self._script_load(args[1])

        elif subcmd == "save":
            if len(args) < 2:
                self._console.print_error("Usage: script save <file>")
                return
            self._script_save(args[1])

        else:
            self._console.print_error(f"Unknown script command: {subcmd}")

    def _script_load(self, file_path: str) -> None:
        """Load and execute a patch script."""
        try:
            script = load_script(file_path)
        except ScriptLoaderError as e:
            self._console.print_error(str(e))
            return

        self._console.print_info(f"Loaded script: {script.description or file_path}")

        # Set architecture if specified
        if script.architecture:
            self._set_arch(script.architecture)

        # Open target file if specified and not already open
        if script.target_file and not self._patcher.is_open:
            if not self._open_file(script.target_file):
                return

        if not self._patcher.is_open:
            self._console.print_error("No file is open. Open a file first or specify 'target' in script")
            return

        # Apply patches
        applied = 0
        for entry in script.patches:
            try:
                if entry.asm:
                    # Assemble and patch
                    result = self._assembler.assemble(entry.asm, entry.offset)
                    self._patcher.patch(entry.offset, result.data, entry.description)
                elif entry.hex:
                    # Direct hex patch
                    data = entry.get_bytes()
                    if data:
                        self._patcher.patch(entry.offset, data, entry.description)
                applied += 1
            except (AssemblerError, PatcherError) as e:
                self._console.print_error(f"Patch at 0x{entry.offset:X} failed: {e}")

        self._console.print_success(f"Applied {applied}/{len(script.patches)} patches")

    def _script_save(self, file_path: str) -> None:
        """Save patch history as script."""
        if not self._patcher.is_open:
            self._console.print_error("No file is open")
            return

        patches = self._patcher.history.patches
        if not patches:
            self._console.print_error("No patches to save")
            return

        script = create_script_from_patches(
            patches,
            architecture=self._arch.name,
            target_file=str(self._patcher.file_path) if self._patcher.file_path else "",
        )

        try:
            save_script(script, file_path)
            self._console.print_success(f"Script saved to: {file_path}")
        except Exception as e:
            self._console.print_error(str(e))

    def _cmd_sections(self, args: list[str]) -> None:
        """Handle sections command."""
        if not self._binary.is_open:
            self._console.print_error("No file is open")
            return

        self._console.print_sections(self._binary.get_sections())

    def _cmd_symbols(self, args: list[str]) -> None:
        """Handle symbols command."""
        if not self._binary.is_open:
            self._console.print_error("No file is open")
            return

        filter_str = args[0] if args else ""
        symbols = self._binary.get_symbols(filter_str)
        self._console.print_symbols(symbols)

    def _cmd_undo(self, args: list[str]) -> None:
        """Handle undo command."""
        if not self._patcher.is_open:
            self._console.print_error("No file is open")
            return

        patch = self._patcher.undo()
        if patch:
            self._console.print_success(f"Undone: {patch}")
        else:
            self._console.print_info("Nothing to undo")
