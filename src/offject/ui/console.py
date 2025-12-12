"""Rich console output for offject."""

from typing import Optional

from rich.console import Console as RichConsole
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax
from rich import box

from offject.core.architectures import Architecture, list_architectures
from offject.core.disassembler import Instruction
from offject.core.patcher import Patch
from offject.binary.parser import BinaryInfo, Section, Symbol


class Console:
    """Rich console output handler."""

    def __init__(self, simple_mode: bool = False):
        """Initialize console.

        Args:
            simple_mode: Use simple text output instead of rich formatting
        """
        self._console = RichConsole()
        self._simple = simple_mode

    def print(self, message: str, style: str = "") -> None:
        """Print a message.

        Args:
            message: Message to print
            style: Rich style string
        """
        if self._simple:
            print(message)
        else:
            self._console.print(message, style=style)

    def print_error(self, message: str) -> None:
        """Print error message.

        Args:
            message: Error message
        """
        if self._simple:
            print(f"Error: {message}")
        else:
            self._console.print(f"[bold red]Error:[/bold red] {message}")

    def print_warning(self, message: str) -> None:
        """Print warning message.

        Args:
            message: Warning message
        """
        if self._simple:
            print(f"Warning: {message}")
        else:
            self._console.print(f"[bold yellow]Warning:[/bold yellow] {message}")

    def print_success(self, message: str) -> None:
        """Print success message.

        Args:
            message: Success message
        """
        if self._simple:
            print(message)
        else:
            self._console.print(f"[bold green]{message}[/bold green]")

    def print_info(self, message: str) -> None:
        """Print info message.

        Args:
            message: Info message
        """
        if self._simple:
            print(message)
        else:
            self._console.print(f"[cyan]{message}[/cyan]")

    def print_banner(
        self,
        file_name: str = "",
        arch_name: str = "",
        offset: int = 0,
        modified: bool = False,
    ) -> None:
        """Print status banner.

        Args:
            file_name: Current file name
            arch_name: Current architecture name
            offset: Current offset
            modified: Whether file is modified
        """
        if self._simple:
            mod = "*" if modified else ""
            print(f"[{file_name}{mod}] Arch: {arch_name} | Offset: 0x{offset:X}")
            return

        mod_indicator = "[red]*[/red]" if modified else ""
        title = f"[bold cyan]Offject v2.0[/bold cyan]"

        content = []
        if file_name:
            content.append(f"[bold]File:[/bold] {file_name}{mod_indicator}")
        if arch_name:
            content.append(f"[bold]Arch:[/bold] {arch_name}")
        content.append(f"[bold]Offset:[/bold] 0x{offset:X}")

        panel = Panel(
            "  ".join(content),
            title=title,
            border_style="cyan",
            box=box.ROUNDED,
        )
        self._console.print(panel)

    def print_binary_info(self, info: BinaryInfo) -> None:
        """Print binary file information.

        Args:
            info: BinaryInfo object
        """
        if self._simple:
            print(f"File:       {info.path.name}")
            print(f"Format:     {info.format.value.upper()}")
            print(f"Size:       {info.size} bytes")
            print(f"Arch:       {info.architecture or 'Unknown'}")
            print(f"Entry:      0x{info.entry_point:X}")
            print(f"Image Base: 0x{info.image_base:X}")
            print(f"Sections:   {len(info.sections)}")
            return

        table = Table(title="Binary Information", box=box.ROUNDED)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("File", info.path.name)
        table.add_row("Format", info.format.value.upper())
        table.add_row("Size", f"{info.size:,} bytes")
        table.add_row("Architecture", info.architecture or "Unknown")
        table.add_row("64-bit", "Yes" if info.is_64bit else "No")
        table.add_row("Entry Point", f"0x{info.entry_point:X}")
        table.add_row("Image Base", f"0x{info.image_base:X}")
        table.add_row("Sections", str(len(info.sections)))

        self._console.print(table)

    def print_sections(self, sections: list[Section]) -> None:
        """Print section list.

        Args:
            sections: List of Section objects
        """
        if not sections:
            self.print_warning("No sections found")
            return

        if self._simple:
            print(f"{'Name':<16} {'Offset':<12} {'Size':<12} {'VAddr':<12} {'VSize':<12}")
            print("-" * 64)
            for sec in sections:
                print(f"{sec.name:<16} 0x{sec.offset:<10X} 0x{sec.size:<10X} "
                      f"0x{sec.virtual_address:<10X} 0x{sec.virtual_size:<10X}")
            return

        table = Table(title="Sections", box=box.ROUNDED)
        table.add_column("Name", style="cyan")
        table.add_column("Offset", style="green")
        table.add_column("Size", style="yellow")
        table.add_column("Virtual Addr", style="magenta")
        table.add_column("Virtual Size", style="blue")

        for sec in sections:
            table.add_row(
                sec.name,
                f"0x{sec.offset:08X}",
                f"0x{sec.size:08X}",
                f"0x{sec.virtual_address:08X}",
                f"0x{sec.virtual_size:08X}",
            )

        self._console.print(table)

    def print_symbols(self, symbols: list[Symbol]) -> None:
        """Print symbol list.

        Args:
            symbols: List of Symbol objects
        """
        if not symbols:
            self.print_warning("No symbols found")
            return

        if self._simple:
            for sym in symbols:
                print(f"0x{sym.address:08X}  {sym.name}")
            return

        table = Table(title="Symbols", box=box.ROUNDED)
        table.add_column("Address", style="green")
        table.add_column("Size", style="yellow")
        table.add_column("Name", style="cyan")

        for sym in symbols[:100]:  # Limit display
            table.add_row(
                f"0x{sym.address:08X}",
                f"0x{sym.size:X}" if sym.size else "-",
                sym.name,
            )

        self._console.print(table)
        if len(symbols) > 100:
            self.print_info(f"... and {len(symbols) - 100} more symbols")

    def print_disassembly(self, instructions: list[Instruction]) -> None:
        """Print disassembly output.

        Args:
            instructions: List of Instruction objects
        """
        if not instructions:
            self.print_warning("No instructions to display")
            return

        if self._simple:
            for insn in instructions:
                print(str(insn))
            return

        for insn in instructions:
            addr = Text(f"0x{insn.address:08X}", style="green")
            hex_bytes = Text(f"{insn.hex_spaced:24s}", style="dim")
            mnemonic = Text(insn.mnemonic, style="bold cyan")
            operands = Text(f" {insn.op_str}" if insn.op_str else "", style="yellow")

            self._console.print(addr, hex_bytes, mnemonic, operands, sep="  ")

    def print_assembly_result(self, hex_str: str, count: int, size: int) -> None:
        """Print assembly result.

        Args:
            hex_str: Hex string of assembled bytes
            count: Number of instructions
            size: Size in bytes
        """
        if self._simple:
            print(f"Assembled: {hex_str} ({count} instruction(s), {size} bytes)")
            return

        self._console.print(
            f"[bold green]Assembled:[/bold green] [yellow]{hex_str}[/yellow] "
            f"[dim]({count} instruction(s), {size} bytes)[/dim]"
        )

    def print_patch_result(self, patch: Patch) -> None:
        """Print patch result.

        Args:
            patch: Patch object
        """
        if self._simple:
            print(f"Patched {len(patch.new_data)} bytes at 0x{patch.offset:X}")
            return

        self._console.print(
            f"[bold green]Patched[/bold green] {len(patch.new_data)} bytes at "
            f"[cyan]0x{patch.offset:X}[/cyan]"
        )

    def print_architectures(self) -> None:
        """Print available architectures."""
        archs = list_architectures()

        if self._simple:
            print("Available architectures:")
            for arch in archs:
                print(f"  {arch.name:<12} - {arch.description}")
            return

        table = Table(title="Supported Architectures", box=box.ROUNDED)
        table.add_column("Name", style="cyan")
        table.add_column("Description", style="green")

        for arch in archs:
            table.add_row(arch.name, arch.description)

        self._console.print(table)

    def print_history(self, patches: list[Patch]) -> None:
        """Print patch history.

        Args:
            patches: List of Patch objects
        """
        if not patches:
            self.print_info("No patches in history")
            return

        if self._simple:
            for i, patch in enumerate(patches, 1):
                print(f"{i}. 0x{patch.offset:08X}: {len(patch.new_data)} bytes")
            return

        table = Table(title="Patch History", box=box.ROUNDED)
        table.add_column("#", style="dim")
        table.add_column("Offset", style="cyan")
        table.add_column("Size", style="yellow")
        table.add_column("Description", style="green")

        for i, patch in enumerate(patches, 1):
            table.add_row(
                str(i),
                f"0x{patch.offset:08X}",
                f"{len(patch.new_data)} bytes",
                patch.description or "-",
            )

        self._console.print(table)

    def print_help(self, commands: dict[str, str]) -> None:
        """Print help information.

        Args:
            commands: Dictionary of command names to descriptions
        """
        if self._simple:
            print("Commands:")
            for cmd, desc in commands.items():
                print(f"  {cmd:<20} {desc}")
            return

        table = Table(title="Commands", box=box.ROUNDED)
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="green")

        for cmd, desc in commands.items():
            table.add_row(cmd, desc)

        self._console.print(table)
