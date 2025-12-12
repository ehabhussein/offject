"""Binary file parser using LIEF for format detection and parsing."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Iterator

import lief


class BinaryFormat(Enum):
    """Supported binary formats."""
    RAW = "raw"
    ELF = "elf"
    PE = "pe"
    MACHO = "macho"


@dataclass
class Section:
    """Binary section information."""
    name: str
    offset: int
    size: int
    virtual_address: int
    virtual_size: int
    characteristics: int = 0

    @property
    def end_offset(self) -> int:
        """End offset of section."""
        return self.offset + self.size

    def contains_offset(self, offset: int) -> bool:
        """Check if offset is within section."""
        return self.offset <= offset < self.end_offset

    def contains_address(self, address: int) -> bool:
        """Check if virtual address is within section."""
        return self.virtual_address <= address < self.virtual_address + self.virtual_size

    def __str__(self) -> str:
        return (
            f"{self.name:16s} offset=0x{self.offset:08X} size=0x{self.size:08X} "
            f"vaddr=0x{self.virtual_address:08X}"
        )


@dataclass
class Symbol:
    """Binary symbol information."""
    name: str
    address: int
    size: int = 0
    type: str = ""

    def __str__(self) -> str:
        return f"0x{self.address:08X} {self.name}"


@dataclass
class BinaryInfo:
    """Information about a binary file."""
    path: Path
    format: BinaryFormat
    size: int
    architecture: str = ""
    entry_point: int = 0
    image_base: int = 0
    sections: list[Section] = field(default_factory=list)
    is_64bit: bool = False

    def __str__(self) -> str:
        bits = "64-bit" if self.is_64bit else "32-bit"
        return f"{self.format.value.upper()} {bits} {self.architecture}"


class BinaryParserError(Exception):
    """Exception for binary parsing errors."""
    pass


class BinaryFile:
    """Binary file parser using LIEF."""

    def __init__(self, file_path: Optional[Path | str] = None):
        """Initialize binary file parser.

        Args:
            file_path: Optional path to binary file
        """
        self._path: Optional[Path] = None
        self._data: Optional[bytes] = None
        self._binary: Optional[lief.Binary] = None
        self._format = BinaryFormat.RAW
        self._info: Optional[BinaryInfo] = None

        if file_path:
            self.open(file_path)

    def open(self, file_path: Path | str) -> BinaryInfo:
        """Open and parse a binary file.

        Args:
            file_path: Path to binary file

        Returns:
            BinaryInfo with parsed information
        """
        path = Path(file_path) if isinstance(file_path, str) else file_path

        if not path.exists():
            raise BinaryParserError(f"File not found: {path}")

        # Read raw data
        with open(path, "rb") as f:
            self._data = f.read()
        self._path = path

        # Try to parse with LIEF
        try:
            self._binary = lief.parse(str(path))
        except Exception:
            self._binary = None

        # Determine format and extract info
        self._detect_format()
        self._extract_info()

        return self._info

    def open_bytes(self, data: bytes, name: str = "<memory>") -> BinaryInfo:
        """Open from bytes.

        Args:
            data: Binary data
            name: Name for display

        Returns:
            BinaryInfo with parsed information
        """
        self._data = data
        self._path = Path(name)

        # Try to parse with LIEF
        try:
            self._binary = lief.parse(list(data))
        except Exception:
            self._binary = None

        self._detect_format()
        self._extract_info()

        return self._info

    def _detect_format(self) -> None:
        """Detect binary format."""
        if self._binary is None:
            self._format = BinaryFormat.RAW
        elif isinstance(self._binary, lief.ELF.Binary):
            self._format = BinaryFormat.ELF
        elif isinstance(self._binary, lief.PE.Binary):
            self._format = BinaryFormat.PE
        elif isinstance(self._binary, lief.MachO.Binary):
            self._format = BinaryFormat.MACHO
        else:
            self._format = BinaryFormat.RAW

    def _extract_info(self) -> None:
        """Extract binary information."""
        sections = []
        entry_point = 0
        image_base = 0
        architecture = ""
        is_64bit = False

        if self._binary is not None:
            # Get entry point
            if hasattr(self._binary, "entrypoint"):
                entry_point = self._binary.entrypoint

            # Get image base
            if hasattr(self._binary, "imagebase"):
                image_base = self._binary.imagebase

            # Get sections
            if hasattr(self._binary, "sections"):
                for sec in self._binary.sections:
                    sections.append(Section(
                        name=sec.name if hasattr(sec, "name") else "",
                        offset=sec.offset if hasattr(sec, "offset") else 0,
                        size=sec.size if hasattr(sec, "size") else 0,
                        virtual_address=sec.virtual_address if hasattr(sec, "virtual_address") else 0,
                        virtual_size=sec.virtual_size if hasattr(sec, "virtual_size") else 0,
                    ))

            # Get architecture info based on format
            if self._format == BinaryFormat.ELF:
                arch_map = {
                    lief.ELF.ARCH.x86_64: ("x86_64", True),
                    lief.ELF.ARCH.i386: ("x86", False),
                    lief.ELF.ARCH.ARM: ("ARM", False),
                    lief.ELF.ARCH.AARCH64: ("ARM64", True),
                    lief.ELF.ARCH.MIPS: ("MIPS", False),
                    lief.ELF.ARCH.PPC: ("PowerPC", False),
                    lief.ELF.ARCH.PPC64: ("PowerPC64", True),
                }
                if hasattr(self._binary, "header") and hasattr(self._binary.header, "machine_type"):
                    arch_info = arch_map.get(self._binary.header.machine_type, ("Unknown", False))
                    architecture, is_64bit = arch_info

            elif self._format == BinaryFormat.PE:
                arch_map = {
                    lief.PE.Header.MACHINE_TYPES.AMD64: ("x86_64", True),
                    lief.PE.Header.MACHINE_TYPES.I386: ("x86", False),
                    lief.PE.Header.MACHINE_TYPES.ARM: ("ARM", False),
                    lief.PE.Header.MACHINE_TYPES.ARM64: ("ARM64", True),
                }
                if hasattr(self._binary, "header") and hasattr(self._binary.header, "machine"):
                    arch_info = arch_map.get(self._binary.header.machine, ("Unknown", False))
                    architecture, is_64bit = arch_info

            elif self._format == BinaryFormat.MACHO:
                if hasattr(self._binary, "header") and hasattr(self._binary.header, "cpu_type"):
                    cpu = self._binary.header.cpu_type
                    if cpu == lief.MachO.Header.CPU_TYPE.x86_64:
                        architecture, is_64bit = "x86_64", True
                    elif cpu == lief.MachO.Header.CPU_TYPE.x86:
                        architecture, is_64bit = "x86", False
                    elif cpu == lief.MachO.Header.CPU_TYPE.ARM64:
                        architecture, is_64bit = "ARM64", True
                    elif cpu == lief.MachO.Header.CPU_TYPE.ARM:
                        architecture, is_64bit = "ARM", False

        self._info = BinaryInfo(
            path=self._path,
            format=self._format,
            size=len(self._data) if self._data else 0,
            architecture=architecture,
            entry_point=entry_point,
            image_base=image_base,
            sections=sections,
            is_64bit=is_64bit,
        )

    @property
    def is_open(self) -> bool:
        """Check if file is open."""
        return self._data is not None

    @property
    def path(self) -> Optional[Path]:
        """Get file path."""
        return self._path

    @property
    def format(self) -> BinaryFormat:
        """Get binary format."""
        return self._format

    @property
    def info(self) -> Optional[BinaryInfo]:
        """Get binary info."""
        return self._info

    @property
    def size(self) -> int:
        """Get file size."""
        return len(self._data) if self._data else 0

    @property
    def data(self) -> bytes:
        """Get raw file data."""
        if self._data is None:
            raise RuntimeError("No file is open")
        return self._data

    def get_sections(self) -> list[Section]:
        """Get all sections.

        Returns:
            List of Section objects
        """
        return self._info.sections if self._info else []

    def get_section(self, name: str) -> Optional[Section]:
        """Get section by name.

        Args:
            name: Section name

        Returns:
            Section object or None
        """
        for section in self.get_sections():
            if section.name == name:
                return section
        return None

    def get_section_at_offset(self, offset: int) -> Optional[Section]:
        """Get section containing offset.

        Args:
            offset: File offset

        Returns:
            Section object or None
        """
        for section in self.get_sections():
            if section.contains_offset(offset):
                return section
        return None

    def get_section_at_address(self, address: int) -> Optional[Section]:
        """Get section containing virtual address.

        Args:
            address: Virtual address

        Returns:
            Section object or None
        """
        for section in self.get_sections():
            if section.contains_address(address):
                return section
        return None

    def get_symbols(self, filter_name: str = "") -> list[Symbol]:
        """Get symbols, optionally filtered.

        Args:
            filter_name: Filter string for symbol names

        Returns:
            List of Symbol objects
        """
        if self._binary is None:
            return []

        symbols = []

        # Try to get symbols based on format
        if hasattr(self._binary, "symbols"):
            for sym in self._binary.symbols:
                if not hasattr(sym, "name") or not sym.name:
                    continue
                if filter_name and filter_name.lower() not in sym.name.lower():
                    continue
                symbols.append(Symbol(
                    name=sym.name,
                    address=sym.value if hasattr(sym, "value") else 0,
                    size=sym.size if hasattr(sym, "size") else 0,
                ))

        return sorted(symbols, key=lambda s: s.address)

    def get_symbol(self, name: str) -> Optional[Symbol]:
        """Get symbol by name.

        Args:
            name: Symbol name

        Returns:
            Symbol object or None
        """
        for sym in self.get_symbols():
            if sym.name == name:
                return sym
        return None

    def get_entry_point(self) -> int:
        """Get entry point address.

        Returns:
            Entry point address
        """
        return self._info.entry_point if self._info else 0

    def get_image_base(self) -> int:
        """Get image base address.

        Returns:
            Image base address
        """
        return self._info.image_base if self._info else 0

    def offset_to_address(self, offset: int) -> int:
        """Convert file offset to virtual address.

        Args:
            offset: File offset

        Returns:
            Virtual address
        """
        section = self.get_section_at_offset(offset)
        if section:
            return section.virtual_address + (offset - section.offset)
        return self.get_image_base() + offset

    def address_to_offset(self, address: int) -> int:
        """Convert virtual address to file offset.

        Args:
            address: Virtual address

        Returns:
            File offset
        """
        section = self.get_section_at_address(address)
        if section:
            return section.offset + (address - section.virtual_address)
        return address - self.get_image_base()

    def read(self, offset: int, size: int) -> bytes:
        """Read bytes at offset.

        Args:
            offset: File offset
            size: Number of bytes

        Returns:
            Bytes read
        """
        if self._data is None:
            raise RuntimeError("No file is open")
        return self._data[offset:offset + size]

    def close(self) -> None:
        """Close the file."""
        self._path = None
        self._data = None
        self._binary = None
        self._format = BinaryFormat.RAW
        self._info = None

    def __repr__(self) -> str:
        if self.is_open:
            return f"BinaryFile({self._path}, format={self._format.value})"
        return "BinaryFile(not open)"
