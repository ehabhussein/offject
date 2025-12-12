"""Architecture definitions for Keystone and Capstone."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

import keystone as ks
import capstone as cs


class ArchType(Enum):
    """Supported architecture types."""
    X86 = "x86"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    PPC = "ppc"
    SPARC = "sparc"


class ModeType(Enum):
    """Supported architecture modes."""
    # x86 modes
    MODE_16 = "16"
    MODE_32 = "32"
    MODE_64 = "64"
    # ARM modes
    ARM = "arm"
    THUMB = "thumb"
    # MIPS modes
    MIPS32 = "mips32"
    MIPS64 = "mips64"
    MICRO = "micro"
    # Endianness
    LITTLE = "little"
    BIG = "big"


@dataclass
class Architecture:
    """Architecture configuration for assembler and disassembler."""

    name: str
    description: str
    ks_arch: int
    ks_mode: int
    cs_arch: int
    cs_mode: int

    def __str__(self) -> str:
        return f"{self.name}: {self.description}"


# Architecture registry
ARCHITECTURES: dict[str, Architecture] = {
    # x86 family
    "x86": Architecture(
        name="x86",
        description="Intel x86 32-bit",
        ks_arch=ks.KS_ARCH_X86,
        ks_mode=ks.KS_MODE_32,
        cs_arch=cs.CS_ARCH_X86,
        cs_mode=cs.CS_MODE_32,
    ),
    "x86_16": Architecture(
        name="x86_16",
        description="Intel x86 16-bit",
        ks_arch=ks.KS_ARCH_X86,
        ks_mode=ks.KS_MODE_16,
        cs_arch=cs.CS_ARCH_X86,
        cs_mode=cs.CS_MODE_16,
    ),
    "x64": Architecture(
        name="x64",
        description="Intel x86 64-bit",
        ks_arch=ks.KS_ARCH_X86,
        ks_mode=ks.KS_MODE_64,
        cs_arch=cs.CS_ARCH_X86,
        cs_mode=cs.CS_MODE_64,
    ),

    # ARM family
    "arm": Architecture(
        name="arm",
        description="ARM 32-bit",
        ks_arch=ks.KS_ARCH_ARM,
        ks_mode=ks.KS_MODE_ARM,
        cs_arch=cs.CS_ARCH_ARM,
        cs_mode=cs.CS_MODE_ARM,
    ),
    "arm_thumb": Architecture(
        name="arm_thumb",
        description="ARM Thumb",
        ks_arch=ks.KS_ARCH_ARM,
        ks_mode=ks.KS_MODE_THUMB,
        cs_arch=cs.CS_ARCH_ARM,
        cs_mode=cs.CS_MODE_THUMB,
    ),
    "arm64": Architecture(
        name="arm64",
        description="ARM 64-bit (AArch64)",
        ks_arch=ks.KS_ARCH_ARM64,
        ks_mode=ks.KS_MODE_LITTLE_ENDIAN,
        cs_arch=cs.CS_ARCH_ARM64,
        cs_mode=cs.CS_MODE_LITTLE_ENDIAN,
    ),

    # MIPS family
    "mips32": Architecture(
        name="mips32",
        description="MIPS 32-bit Little Endian",
        ks_arch=ks.KS_ARCH_MIPS,
        ks_mode=ks.KS_MODE_MIPS32 + ks.KS_MODE_LITTLE_ENDIAN,
        cs_arch=cs.CS_ARCH_MIPS,
        cs_mode=cs.CS_MODE_MIPS32 + cs.CS_MODE_LITTLE_ENDIAN,
    ),
    "mips32be": Architecture(
        name="mips32be",
        description="MIPS 32-bit Big Endian",
        ks_arch=ks.KS_ARCH_MIPS,
        ks_mode=ks.KS_MODE_MIPS32 + ks.KS_MODE_BIG_ENDIAN,
        cs_arch=cs.CS_ARCH_MIPS,
        cs_mode=cs.CS_MODE_MIPS32 + cs.CS_MODE_BIG_ENDIAN,
    ),
    "mips64": Architecture(
        name="mips64",
        description="MIPS 64-bit Little Endian",
        ks_arch=ks.KS_ARCH_MIPS,
        ks_mode=ks.KS_MODE_MIPS64 + ks.KS_MODE_LITTLE_ENDIAN,
        cs_arch=cs.CS_ARCH_MIPS,
        cs_mode=cs.CS_MODE_MIPS64 + cs.CS_MODE_LITTLE_ENDIAN,
    ),
    "mips64be": Architecture(
        name="mips64be",
        description="MIPS 64-bit Big Endian",
        ks_arch=ks.KS_ARCH_MIPS,
        ks_mode=ks.KS_MODE_MIPS64 + ks.KS_MODE_BIG_ENDIAN,
        cs_arch=cs.CS_ARCH_MIPS,
        cs_mode=cs.CS_MODE_MIPS64 + cs.CS_MODE_BIG_ENDIAN,
    ),

    # PowerPC family
    "ppc32": Architecture(
        name="ppc32",
        description="PowerPC 32-bit Big Endian",
        ks_arch=ks.KS_ARCH_PPC,
        ks_mode=ks.KS_MODE_PPC32 + ks.KS_MODE_BIG_ENDIAN,
        cs_arch=cs.CS_ARCH_PPC,
        cs_mode=cs.CS_MODE_32 + cs.CS_MODE_BIG_ENDIAN,
    ),
    "ppc64": Architecture(
        name="ppc64",
        description="PowerPC 64-bit Big Endian",
        ks_arch=ks.KS_ARCH_PPC,
        ks_mode=ks.KS_MODE_PPC64 + ks.KS_MODE_BIG_ENDIAN,
        cs_arch=cs.CS_ARCH_PPC,
        cs_mode=cs.CS_MODE_64 + cs.CS_MODE_BIG_ENDIAN,
    ),
    "ppc64le": Architecture(
        name="ppc64le",
        description="PowerPC 64-bit Little Endian",
        ks_arch=ks.KS_ARCH_PPC,
        ks_mode=ks.KS_MODE_PPC64 + ks.KS_MODE_LITTLE_ENDIAN,
        cs_arch=cs.CS_ARCH_PPC,
        cs_mode=cs.CS_MODE_64 + cs.CS_MODE_LITTLE_ENDIAN,
    ),

    # SPARC family
    "sparc32": Architecture(
        name="sparc32",
        description="SPARC 32-bit",
        ks_arch=ks.KS_ARCH_SPARC,
        ks_mode=ks.KS_MODE_SPARC32 + ks.KS_MODE_BIG_ENDIAN,
        cs_arch=cs.CS_ARCH_SPARC,
        cs_mode=cs.CS_MODE_BIG_ENDIAN,
    ),
    "sparc64": Architecture(
        name="sparc64",
        description="SPARC 64-bit",
        ks_arch=ks.KS_ARCH_SPARC,
        ks_mode=ks.KS_MODE_SPARC64 + ks.KS_MODE_BIG_ENDIAN,
        cs_arch=cs.CS_ARCH_SPARC,
        cs_mode=cs.CS_MODE_V9 + cs.CS_MODE_BIG_ENDIAN,
    ),
}

# Aliases for common names
ARCHITECTURE_ALIASES: dict[str, str] = {
    "i386": "x86",
    "i686": "x86",
    "x86_32": "x86",
    "amd64": "x64",
    "x86_64": "x64",
    "thumb": "arm_thumb",
    "aarch64": "arm64",
    "mips": "mips32",
    "mipsle": "mips32",
    "mipsbe": "mips32be",
    "ppc": "ppc32",
    "powerpc": "ppc32",
    "powerpc64": "ppc64",
    "sparc": "sparc32",
}


def get_architecture(name: str) -> Optional[Architecture]:
    """Get architecture by name or alias.

    Args:
        name: Architecture name or alias (case-insensitive)

    Returns:
        Architecture object or None if not found
    """
    name_lower = name.lower()

    # Check direct match
    if name_lower in ARCHITECTURES:
        return ARCHITECTURES[name_lower]

    # Check aliases
    if name_lower in ARCHITECTURE_ALIASES:
        return ARCHITECTURES[ARCHITECTURE_ALIASES[name_lower]]

    return None


def list_architectures() -> list[Architecture]:
    """Get list of all supported architectures.

    Returns:
        List of Architecture objects
    """
    return list(ARCHITECTURES.values())


def get_architecture_names() -> list[str]:
    """Get list of all architecture names and aliases.

    Returns:
        Sorted list of architecture names
    """
    names = set(ARCHITECTURES.keys())
    names.update(ARCHITECTURE_ALIASES.keys())
    return sorted(names)
