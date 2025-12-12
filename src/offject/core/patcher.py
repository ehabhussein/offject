"""Binary patching with undo/redo support."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, BinaryIO
import io


@dataclass
class Patch:
    """A single patch operation."""

    offset: int
    old_data: bytes
    new_data: bytes
    description: str = ""

    @property
    def size(self) -> int:
        """Size of the patch."""
        return len(self.new_data)

    def __str__(self) -> str:
        desc = f" ({self.description})" if self.description else ""
        return f"Patch @ 0x{self.offset:X}: {len(self.new_data)} bytes{desc}"


@dataclass
class PatchHistory:
    """History of patches for undo/redo."""

    patches: list[Patch] = field(default_factory=list)
    undo_stack: list[Patch] = field(default_factory=list)
    redo_stack: list[Patch] = field(default_factory=list)

    def add(self, patch: Patch) -> None:
        """Add a patch to history."""
        self.patches.append(patch)
        self.undo_stack.append(patch)
        self.redo_stack.clear()  # Clear redo stack on new patch

    def can_undo(self) -> bool:
        """Check if undo is possible."""
        return len(self.undo_stack) > 0

    def can_redo(self) -> bool:
        """Check if redo is possible."""
        return len(self.redo_stack) > 0

    def pop_undo(self) -> Optional[Patch]:
        """Pop last patch for undo."""
        if self.undo_stack:
            patch = self.undo_stack.pop()
            self.redo_stack.append(patch)
            return patch
        return None

    def pop_redo(self) -> Optional[Patch]:
        """Pop last undone patch for redo."""
        if self.redo_stack:
            patch = self.redo_stack.pop()
            self.undo_stack.append(patch)
            return patch
        return None

    def clear(self) -> None:
        """Clear all history."""
        self.patches.clear()
        self.undo_stack.clear()
        self.redo_stack.clear()


class PatcherError(Exception):
    """Exception for patching errors."""
    pass


class Patcher:
    """Binary patcher with undo/redo support."""

    def __init__(self, file_path: Optional[Path | str] = None):
        """Initialize patcher.

        Args:
            file_path: Optional path to binary file
        """
        self._file_path: Optional[Path] = None
        self._data: Optional[bytearray] = None
        self._original_data: Optional[bytes] = None
        self._history = PatchHistory()
        self._modified = False

        if file_path:
            self.open(file_path)

    def open(self, file_path: Path | str) -> None:
        """Open a binary file.

        Args:
            file_path: Path to binary file
        """
        path = Path(file_path) if isinstance(file_path, str) else file_path

        if not path.exists():
            raise PatcherError(f"File not found: {path}")

        try:
            with open(path, "rb") as f:
                data = f.read()
            self._file_path = path
            self._original_data = data
            self._data = bytearray(data)
            self._history.clear()
            self._modified = False
        except IOError as e:
            raise PatcherError(f"Failed to read file: {e}")

    def open_bytes(self, data: bytes, name: str = "<memory>") -> None:
        """Open from bytes.

        Args:
            data: Binary data
            name: Optional name for the data
        """
        self._file_path = Path(name)
        self._original_data = data
        self._data = bytearray(data)
        self._history.clear()
        self._modified = False

    @property
    def is_open(self) -> bool:
        """Check if a file is open."""
        return self._data is not None

    @property
    def file_path(self) -> Optional[Path]:
        """Get current file path."""
        return self._file_path

    @property
    def size(self) -> int:
        """Get file size."""
        return len(self._data) if self._data else 0

    @property
    def modified(self) -> bool:
        """Check if file has been modified."""
        return self._modified

    @property
    def history(self) -> PatchHistory:
        """Get patch history."""
        return self._history

    def _ensure_open(self) -> None:
        """Ensure a file is open."""
        if not self.is_open:
            raise PatcherError("No file is open")

    def read(self, offset: int, size: int) -> bytes:
        """Read bytes from file.

        Args:
            offset: Offset to read from
            size: Number of bytes to read

        Returns:
            Bytes read
        """
        self._ensure_open()

        if offset < 0 or offset >= len(self._data):
            raise PatcherError(f"Offset 0x{offset:X} out of bounds")

        end = min(offset + size, len(self._data))
        return bytes(self._data[offset:end])

    def patch(
        self,
        offset: int,
        data: bytes,
        description: str = "",
    ) -> Patch:
        """Apply a patch.

        Args:
            offset: Offset to patch at
            data: Bytes to write
            description: Optional description of the patch

        Returns:
            Patch object
        """
        self._ensure_open()

        if offset < 0:
            raise PatcherError(f"Invalid offset: 0x{offset:X}")

        if offset + len(data) > len(self._data):
            raise PatcherError(
                f"Patch extends beyond file end (0x{offset:X} + {len(data)} > 0x{len(self._data):X})"
            )

        # Save old data for undo
        old_data = bytes(self._data[offset:offset + len(data)])

        # Apply patch
        self._data[offset:offset + len(data)] = data

        # Create patch record
        patch = Patch(
            offset=offset,
            old_data=old_data,
            new_data=data,
            description=description,
        )
        self._history.add(patch)
        self._modified = True

        return patch

    def undo(self) -> Optional[Patch]:
        """Undo last patch.

        Returns:
            Undone patch or None
        """
        self._ensure_open()

        patch = self._history.pop_undo()
        if patch:
            # Restore old data
            self._data[patch.offset:patch.offset + len(patch.old_data)] = patch.old_data
            self._modified = self._data != self._original_data
            return patch
        return None

    def redo(self) -> Optional[Patch]:
        """Redo last undone patch.

        Returns:
            Redone patch or None
        """
        self._ensure_open()

        patch = self._history.pop_redo()
        if patch:
            # Reapply new data
            self._data[patch.offset:patch.offset + len(patch.new_data)] = patch.new_data
            self._modified = True
            return patch
        return None

    def save(self, file_path: Optional[Path | str] = None) -> Path:
        """Save patched file.

        Args:
            file_path: Output path (defaults to original path)

        Returns:
            Path file was saved to
        """
        self._ensure_open()

        path = file_path or self._file_path
        if path is None:
            raise PatcherError("No output path specified")

        path = Path(path) if isinstance(path, str) else path

        try:
            with open(path, "wb") as f:
                f.write(self._data)
            return path
        except IOError as e:
            raise PatcherError(f"Failed to save file: {e}")

    def get_data(self) -> bytes:
        """Get current file data.

        Returns:
            File data as bytes
        """
        self._ensure_open()
        return bytes(self._data)

    def get_original_data(self) -> bytes:
        """Get original file data.

        Returns:
            Original file data
        """
        self._ensure_open()
        return self._original_data

    def reset(self) -> None:
        """Reset to original data."""
        self._ensure_open()
        self._data = bytearray(self._original_data)
        self._history.clear()
        self._modified = False

    def close(self) -> None:
        """Close the file."""
        self._file_path = None
        self._data = None
        self._original_data = None
        self._history.clear()
        self._modified = False

    def __repr__(self) -> str:
        if self.is_open:
            return f"Patcher(file={self._file_path}, size=0x{self.size:X}, modified={self._modified})"
        return "Patcher(not open)"
