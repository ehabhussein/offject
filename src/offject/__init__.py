"""Offject - Cross-platform multi-architecture binary patching tool."""

__version__ = "2.0.0"
__author__ = "Ehab Hussein"

from offject.core.assembler import Assembler
from offject.core.disassembler import Disassembler
from offject.core.patcher import Patcher
from offject.core.architectures import Architecture, get_architecture, list_architectures

__all__ = [
    "Assembler",
    "Disassembler",
    "Patcher",
    "Architecture",
    "get_architecture",
    "list_architectures",
    "__version__",
]
