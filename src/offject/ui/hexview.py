"""Hex view display using Rich."""

from typing import Optional

from rich.console import Console as RichConsole
from rich.table import Table
from rich.text import Text
from rich import box

from offject.utils.helpers import bytes_to_ascii


class HexView:
    """Hex dump display with highlighting."""

    def __init__(
        self,
        bytes_per_line: int = 16,
        simple_mode: bool = False,
    ):
        """Initialize hex view.

        Args:
            bytes_per_line: Number of bytes per line
            simple_mode: Use simple text output
        """
        self._bytes_per_line = bytes_per_line
        self._simple = simple_mode
        self._console = RichConsole()
        self._highlights: dict[int, str] = {}  # offset -> style

    def set_highlight(self, start: int, length: int, style: str = "bold yellow") -> None:
        """Set highlight for byte range.

        Args:
            start: Start offset
            length: Number of bytes
            style: Rich style string
        """
        for i in range(start, start + length):
            self._highlights[i] = style

    def clear_highlights(self) -> None:
        """Clear all highlights."""
        self._highlights.clear()

    def format_hex_line(
        self,
        offset: int,
        data: bytes,
        base_offset: int = 0,
    ) -> tuple[str, str, str]:
        """Format a single hex line.

        Args:
            offset: Line offset
            data: Bytes for this line
            base_offset: Base offset for highlight calculation

        Returns:
            Tuple of (offset_str, hex_str, ascii_str)
        """
        offset_str = f"{offset:08X}"

        # Format hex bytes
        hex_parts = []
        for i, byte in enumerate(data):
            hex_parts.append(f"{byte:02X}")
        # Pad if needed
        while len(hex_parts) < self._bytes_per_line:
            hex_parts.append("  ")

        # Group by 8 bytes
        mid = self._bytes_per_line // 2
        hex_str = " ".join(hex_parts[:mid]) + "  " + " ".join(hex_parts[mid:])

        # ASCII representation
        ascii_str = bytes_to_ascii(data)

        return offset_str, hex_str, ascii_str

    def print(
        self,
        data: bytes,
        start_offset: int = 0,
        highlight_ranges: Optional[list[tuple[int, int, str]]] = None,
    ) -> None:
        """Print hex dump.

        Args:
            data: Data to display
            start_offset: Starting offset
            highlight_ranges: List of (start, length, style) tuples
        """
        if highlight_ranges:
            for start, length, style in highlight_ranges:
                self.set_highlight(start, length, style)

        if self._simple:
            self._print_simple(data, start_offset)
        else:
            self._print_rich(data, start_offset)

        self.clear_highlights()

    def _print_simple(self, data: bytes, start_offset: int) -> None:
        """Print simple text hex dump.

        Args:
            data: Data to display
            start_offset: Starting offset
        """
        offset = start_offset
        for i in range(0, len(data), self._bytes_per_line):
            chunk = data[i:i + self._bytes_per_line]
            offset_str, hex_str, ascii_str = self.format_hex_line(offset, chunk, start_offset)
            print(f"{offset_str}  {hex_str}  |{ascii_str}|")
            offset += len(chunk)

    def _print_rich(self, data: bytes, start_offset: int) -> None:
        """Print rich hex dump with colors and highlights.

        Args:
            data: Data to display
            start_offset: Starting offset
        """
        offset = start_offset
        for i in range(0, len(data), self._bytes_per_line):
            chunk = data[i:i + self._bytes_per_line]

            # Build offset text
            offset_text = Text(f"{offset:08X}", style="green")

            # Build hex text with highlights
            hex_text = Text()
            for j, byte in enumerate(chunk):
                abs_offset = start_offset + i + j
                style = self._highlights.get(abs_offset, "")
                hex_text.append(f"{byte:02X}", style=style)
                if j < len(chunk) - 1:
                    if j == (self._bytes_per_line // 2) - 1:
                        hex_text.append("  ")  # Extra space at midpoint
                    else:
                        hex_text.append(" ")

            # Pad hex if needed
            remaining = self._bytes_per_line - len(chunk)
            if remaining > 0:
                padding = "   " * remaining
                if len(chunk) <= self._bytes_per_line // 2:
                    padding = " " + padding
                hex_text.append(padding)

            # Build ASCII text with highlights
            ascii_text = Text("|", style="dim")
            for j, byte in enumerate(chunk):
                abs_offset = start_offset + i + j
                style = self._highlights.get(abs_offset, "dim")
                char = chr(byte) if 0x20 <= byte <= 0x7E else "."
                ascii_text.append(char, style=style)
            # Pad ASCII if needed
            ascii_text.append("." * remaining, style="dim")
            ascii_text.append("|", style="dim")

            self._console.print(offset_text, " ", hex_text, " ", ascii_text, sep="")
            offset += len(chunk)

    def print_comparison(
        self,
        old_data: bytes,
        new_data: bytes,
        offset: int = 0,
    ) -> None:
        """Print side-by-side comparison of old and new data.

        Args:
            old_data: Original data
            new_data: New data
            offset: Starting offset
        """
        if self._simple:
            print("Old:")
            self._print_simple(old_data, offset)
            print("New:")
            self._print_simple(new_data, offset)
            return

        self._console.print("[bold]Old:[/bold]", style="red")
        # Highlight differences in old data
        for i, (old_byte, new_byte) in enumerate(zip(old_data, new_data)):
            if old_byte != new_byte:
                self.set_highlight(offset + i, 1, "bold red")
        self._print_rich(old_data, offset)
        self.clear_highlights()

        self._console.print("[bold]New:[/bold]", style="green")
        # Highlight differences in new data
        for i, (old_byte, new_byte) in enumerate(zip(old_data, new_data)):
            if old_byte != new_byte:
                self.set_highlight(offset + i, 1, "bold green")
        self._print_rich(new_data, offset)
        self.clear_highlights()

    def format_inline(self, data: bytes, max_bytes: int = 16) -> str:
        """Format bytes as inline hex string.

        Args:
            data: Bytes to format
            max_bytes: Maximum bytes to show

        Returns:
            Formatted string
        """
        if len(data) <= max_bytes:
            return " ".join(f"{b:02X}" for b in data)
        else:
            shown = " ".join(f"{b:02X}" for b in data[:max_bytes])
            return f"{shown} ... ({len(data)} bytes total)"
