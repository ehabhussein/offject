"""Keystone assembler wrapper."""

from dataclasses import dataclass
from typing import Optional

import keystone as ks

from offject.core.architectures import Architecture, get_architecture


@dataclass
class AssemblyResult:
    """Result of an assembly operation."""

    code: str
    data: bytes
    count: int
    address: int

    @property
    def hex(self) -> str:
        """Get hex string representation."""
        return self.data.hex()

    @property
    def hex_spaced(self) -> str:
        """Get hex string with spaces between bytes."""
        return " ".join(f"{b:02X}" for b in self.data)

    def __len__(self) -> int:
        return len(self.data)

    def __str__(self) -> str:
        return f"{self.hex_spaced} ({self.count} instruction(s), {len(self.data)} bytes)"


class AssemblerError(Exception):
    """Exception raised for assembly errors."""

    def __init__(self, message: str, code: str, address: int = 0):
        self.code = code
        self.address = address
        super().__init__(message)


class Assembler:
    """Multi-architecture assembler using Keystone engine."""

    def __init__(self, arch: Architecture | str = "x86"):
        """Initialize assembler with architecture.

        Args:
            arch: Architecture object or name string
        """
        if isinstance(arch, str):
            resolved = get_architecture(arch)
            if resolved is None:
                raise ValueError(f"Unknown architecture: {arch}")
            arch = resolved

        self._arch = arch
        self._engine: Optional[ks.Ks] = None
        self._init_engine()

    def _init_engine(self) -> None:
        """Initialize Keystone engine."""
        try:
            self._engine = ks.Ks(self._arch.ks_arch, self._arch.ks_mode)
        except ks.KsError as e:
            raise AssemblerError(
                f"Failed to initialize assembler for {self._arch.name}: {e}",
                code="",
            )

    @property
    def architecture(self) -> Architecture:
        """Get current architecture."""
        return self._arch

    def set_architecture(self, arch: Architecture | str) -> None:
        """Change architecture.

        Args:
            arch: Architecture object or name string
        """
        if isinstance(arch, str):
            resolved = get_architecture(arch)
            if resolved is None:
                raise ValueError(f"Unknown architecture: {arch}")
            arch = resolved

        self._arch = arch
        self._init_engine()

    def assemble(self, code: str, address: int = 0) -> AssemblyResult:
        """Assemble code to machine code.

        Args:
            code: Assembly code string (can be multiple instructions separated by ; or newlines)
            address: Base address for assembly (affects relative addressing)

        Returns:
            AssemblyResult with assembled bytes

        Raises:
            AssemblerError: If assembly fails
        """
        if not code.strip():
            raise AssemblerError("Empty code", code=code, address=address)

        try:
            encoding, count = self._engine.asm(code, address)

            if encoding is None:
                raise AssemblerError(
                    f"Assembly failed for: {code}",
                    code=code,
                    address=address,
                )

            return AssemblyResult(
                code=code,
                data=bytes(encoding),
                count=count,
                address=address,
            )

        except ks.KsError as e:
            raise AssemblerError(
                f"Assembly error: {e}",
                code=code,
                address=address,
            )

    def assemble_to_bytes(self, code: str, address: int = 0) -> bytes:
        """Assemble code and return only bytes.

        Args:
            code: Assembly code string
            address: Base address for assembly

        Returns:
            Assembled bytes
        """
        return self.assemble(code, address).data

    def assemble_to_hex(self, code: str, address: int = 0) -> str:
        """Assemble code and return hex string.

        Args:
            code: Assembly code string
            address: Base address for assembly

        Returns:
            Hex string of assembled bytes
        """
        return self.assemble(code, address).hex

    def validate(self, code: str, address: int = 0) -> tuple[bool, str]:
        """Validate if code can be assembled.

        Args:
            code: Assembly code string
            address: Base address for assembly

        Returns:
            Tuple of (success, error_message)
        """
        try:
            self.assemble(code, address)
            return True, ""
        except AssemblerError as e:
            return False, str(e)

    def __repr__(self) -> str:
        return f"Assembler(arch={self._arch.name})"
