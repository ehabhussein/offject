"""Capstone disassembler wrapper."""

from dataclasses import dataclass
from typing import Iterator, Optional

import capstone as cs

from offject.core.architectures import Architecture, get_architecture


@dataclass
class Instruction:
    """Disassembled instruction."""

    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes: bytes

    @property
    def hex(self) -> str:
        """Get hex string of instruction bytes."""
        return self.bytes.hex()

    @property
    def hex_spaced(self) -> str:
        """Get hex string with spaces."""
        return " ".join(f"{b:02x}" for b in self.bytes)

    @property
    def assembly(self) -> str:
        """Get full assembly string."""
        if self.op_str:
            return f"{self.mnemonic} {self.op_str}"
        return self.mnemonic

    def __str__(self) -> str:
        return f"0x{self.address:08x}: {self.hex_spaced:24s} {self.assembly}"

    def __len__(self) -> int:
        return self.size


class DisassemblerError(Exception):
    """Exception raised for disassembly errors."""

    def __init__(self, message: str, address: int = 0):
        self.address = address
        super().__init__(message)


class Disassembler:
    """Multi-architecture disassembler using Capstone engine."""

    def __init__(self, arch: Architecture | str = "x86"):
        """Initialize disassembler with architecture.

        Args:
            arch: Architecture object or name string
        """
        if isinstance(arch, str):
            resolved = get_architecture(arch)
            if resolved is None:
                raise ValueError(f"Unknown architecture: {arch}")
            arch = resolved

        self._arch = arch
        self._engine: Optional[cs.Cs] = None
        self._init_engine()

    def _init_engine(self) -> None:
        """Initialize Capstone engine."""
        try:
            self._engine = cs.Cs(self._arch.cs_arch, self._arch.cs_mode)
            self._engine.detail = True
        except cs.CsError as e:
            raise DisassemblerError(
                f"Failed to initialize disassembler for {self._arch.name}: {e}"
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

    def disassemble(
        self,
        data: bytes,
        address: int = 0,
        count: int = 0,
    ) -> list[Instruction]:
        """Disassemble bytes to instructions.

        Args:
            data: Bytes to disassemble
            address: Base address for disassembly
            count: Maximum number of instructions (0 = all)

        Returns:
            List of Instruction objects
        """
        if not data:
            return []

        instructions = []
        for insn in self._engine.disasm(data, address):
            instructions.append(
                Instruction(
                    address=insn.address,
                    size=insn.size,
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    bytes=bytes(insn.bytes),
                )
            )
            if count > 0 and len(instructions) >= count:
                break

        return instructions

    def disassemble_iter(
        self,
        data: bytes,
        address: int = 0,
    ) -> Iterator[Instruction]:
        """Iterate over disassembled instructions.

        Args:
            data: Bytes to disassemble
            address: Base address for disassembly

        Yields:
            Instruction objects
        """
        for insn in self._engine.disasm(data, address):
            yield Instruction(
                address=insn.address,
                size=insn.size,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                bytes=bytes(insn.bytes),
            )

    def disassemble_one(
        self,
        data: bytes,
        address: int = 0,
    ) -> Optional[Instruction]:
        """Disassemble single instruction.

        Args:
            data: Bytes to disassemble
            address: Base address

        Returns:
            Instruction object or None if disassembly fails
        """
        instructions = self.disassemble(data, address, count=1)
        return instructions[0] if instructions else None

    def disassemble_to_text(
        self,
        data: bytes,
        address: int = 0,
        count: int = 0,
    ) -> str:
        """Disassemble and return formatted text.

        Args:
            data: Bytes to disassemble
            address: Base address
            count: Maximum number of instructions

        Returns:
            Formatted disassembly text
        """
        instructions = self.disassemble(data, address, count)
        return "\n".join(str(insn) for insn in instructions)

    def __repr__(self) -> str:
        return f"Disassembler(arch={self._arch.name})"
