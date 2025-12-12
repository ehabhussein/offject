"""Raw binary file operations."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Iterator

from offject.utils.helpers import bytes_to_ascii, chunks


@dataclass
class FileInfo:
    """Basic file information."""

    path: Path
    size: int
    format: str = "raw"

    def __str__(self) -> str:
        return f"{self.path.name} ({self.format}, {self.size} bytes)"


class RawFile:
    """Raw binary file handler."""

    def __init__(self, file_path: Optional[Path | str] = None):
        """Initialize raw file handler.

        Args:
            file_path: Optional path to file
        """
        self._path: Optional[Path] = None
        self._data: Optional[bytes] = None

        if file_path:
            self.open(file_path)

    def open(self, file_path: Path | str) -> None:
        """Open a file.

        Args:
            file_path: Path to file
        """
        path = Path(file_path) if isinstance(file_path, str) else file_path

        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        with open(path, "rb") as f:
            self._data = f.read()
        self._path = path

    def open_bytes(self, data: bytes, name: str = "<memory>") -> None:
        """Open from bytes.

        Args:
            data: Binary data
            name: Name for the data
        """
        self._data = data
        self._path = Path(name)

    @property
    def is_open(self) -> bool:
        """Check if file is open."""
        return self._data is not None

    @property
    def path(self) -> Optional[Path]:
        """Get file path."""
        return self._path

    @property
    def size(self) -> int:
        """Get file size."""
        return len(self._data) if self._data else 0

    @property
    def data(self) -> bytes:
        """Get file data."""
        if self._data is None:
            raise RuntimeError("No file is open")
        return self._data

    def info(self) -> FileInfo:
        """Get file information.

        Returns:
            FileInfo object
        """
        if not self.is_open:
            raise RuntimeError("No file is open")

        return FileInfo(
            path=self._path,
            size=self.size,
            format="raw",
        )

    def read(self, offset: int, size: int) -> bytes:
        """Read bytes at offset.

        Args:
            offset: Offset to read from
            size: Number of bytes

        Returns:
            Bytes read
        """
        if not self.is_open:
            raise RuntimeError("No file is open")

        if offset < 0 or offset >= len(self._data):
            raise ValueError(f"Offset {offset} out of bounds")

        return self._data[offset:offset + size]

    def read_all(self) -> bytes:
        """Read entire file.

        Returns:
            All file data
        """
        if not self.is_open:
            raise RuntimeError("No file is open")
        return self._data

    def find(self, pattern: bytes, start: int = 0) -> int:
        """Find pattern in file.

        Args:
            pattern: Bytes to find
            start: Start offset

        Returns:
            Offset of pattern or -1 if not found
        """
        if not self.is_open:
            raise RuntimeError("No file is open")
        return self._data.find(pattern, start)

    def find_all(self, pattern: bytes) -> list[int]:
        """Find all occurrences of pattern.

        Args:
            pattern: Bytes to find

        Returns:
            List of offsets
        """
        if not self.is_open:
            raise RuntimeError("No file is open")

        offsets = []
        start = 0
        while True:
            pos = self._data.find(pattern, start)
            if pos == -1:
                break
            offsets.append(pos)
            start = pos + 1
        return offsets

    def iter_chunks(self, chunk_size: int = 16) -> Iterator[tuple[int, bytes]]:
        """Iterate over file in chunks.

        Args:
            chunk_size: Size of each chunk

        Yields:
            Tuples of (offset, chunk_data)
        """
        if not self.is_open:
            raise RuntimeError("No file is open")

        offset = 0
        for chunk in chunks(self._data, chunk_size):
            yield offset, chunk
            offset += len(chunk)

    def close(self) -> None:
        """Close the file."""
        self._path = None
        self._data = None

    def __repr__(self) -> str:
        if self.is_open:
            return f"RawFile({self._path}, size={self.size})"
        return "RawFile(not open)"
