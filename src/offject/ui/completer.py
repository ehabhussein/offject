"""Command completion for the REPL."""

from typing import Iterable, Optional

from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document

from offject.core.architectures import get_architecture_names


# REPL commands
COMMANDS = {
    "arch": "Set/show architecture",
    "asm": "Assemble instructions",
    "clear": "Clear assembled buffer",
    "disasm": "Disassemble at offset",
    "exit": "Exit offject",
    "goto": "Go to offset or symbol",
    "help": "Show help",
    "hex": "Show hex dump",
    "history": "Show patch history",
    "info": "Show binary info",
    "open": "Open file",
    "patch": "Apply assembled bytes",
    "quit": "Exit offject",
    "redo": "Redo last undone patch",
    "save": "Save file",
    "script": "Load/save patch script",
    "sections": "List sections",
    "symbols": "List symbols",
    "undo": "Undo last patch",
}

# Subcommands
SUBCOMMANDS = {
    "script": ["load", "save"],
    "help": list(COMMANDS.keys()),
}

# Common x86 instructions for completion
X86_MNEMONICS = [
    "mov", "push", "pop", "call", "ret", "jmp", "je", "jne", "jz", "jnz",
    "add", "sub", "mul", "div", "inc", "dec", "and", "or", "xor", "not",
    "shl", "shr", "cmp", "test", "lea", "nop", "int", "syscall", "leave",
    "enter", "xchg", "movzx", "movsx", "cdq", "rep", "movsb", "stosb",
]

# Common ARM instructions for completion
ARM_MNEMONICS = [
    "mov", "mvn", "add", "sub", "mul", "and", "orr", "eor", "bic",
    "ldr", "str", "ldm", "stm", "push", "pop", "b", "bl", "bx", "blx",
    "cmp", "cmn", "tst", "teq", "lsl", "lsr", "asr", "ror", "nop",
    "svc", "swi", "adr", "adrl",
]


class OffjectCompleter(Completer):
    """Command completer for offject REPL."""

    def __init__(self, arch: str = "x86"):
        """Initialize completer.

        Args:
            arch: Current architecture name
        """
        self._arch = arch
        self._mnemonics = self._get_mnemonics(arch)
        self._symbols: list[str] = []
        self._sections: list[str] = []

    def _get_mnemonics(self, arch: str) -> list[str]:
        """Get instruction mnemonics for architecture.

        Args:
            arch: Architecture name

        Returns:
            List of mnemonic strings
        """
        arch_lower = arch.lower()
        if "x86" in arch_lower or "x64" in arch_lower or "i386" in arch_lower:
            return X86_MNEMONICS
        elif "arm" in arch_lower:
            return ARM_MNEMONICS
        return []

    def set_architecture(self, arch: str) -> None:
        """Update architecture for completion.

        Args:
            arch: Architecture name
        """
        self._arch = arch
        self._mnemonics = self._get_mnemonics(arch)

    def set_symbols(self, symbols: list[str]) -> None:
        """Update available symbols.

        Args:
            symbols: List of symbol names
        """
        self._symbols = symbols

    def set_sections(self, sections: list[str]) -> None:
        """Update available sections.

        Args:
            sections: List of section names
        """
        self._sections = sections

    def get_completions(
        self,
        document: Document,
        complete_event,
    ) -> Iterable[Completion]:
        """Get completions for current input.

        Args:
            document: Current document
            complete_event: Completion event

        Yields:
            Completion objects
        """
        text = document.text_before_cursor
        words = text.split()

        if not words:
            # Show all commands
            for cmd, desc in COMMANDS.items():
                yield Completion(cmd, display_meta=desc)
            return

        # First word - command completion
        if len(words) == 1 and not text.endswith(" "):
            word = words[0].lower()
            for cmd, desc in COMMANDS.items():
                if cmd.startswith(word):
                    yield Completion(
                        cmd,
                        start_position=-len(word),
                        display_meta=desc,
                    )
            return

        # Subcommand or argument completion
        cmd = words[0].lower()

        if cmd == "arch" and (len(words) == 1 or (len(words) == 2 and not text.endswith(" "))):
            # Architecture name completion
            prefix = words[1].lower() if len(words) > 1 else ""
            for arch_name in get_architecture_names():
                if arch_name.startswith(prefix):
                    yield Completion(
                        arch_name,
                        start_position=-len(prefix) if prefix else 0,
                    )

        elif cmd == "script":
            # Script subcommand completion
            if len(words) == 1 or (len(words) == 2 and not text.endswith(" ")):
                prefix = words[1].lower() if len(words) > 1 else ""
                for subcmd in SUBCOMMANDS["script"]:
                    if subcmd.startswith(prefix):
                        yield Completion(
                            subcmd,
                            start_position=-len(prefix) if prefix else 0,
                        )

        elif cmd == "help":
            # Help topic completion
            if len(words) == 1 or (len(words) == 2 and not text.endswith(" ")):
                prefix = words[1].lower() if len(words) > 1 else ""
                for topic in COMMANDS.keys():
                    if topic.startswith(prefix):
                        yield Completion(
                            topic,
                            start_position=-len(prefix) if prefix else 0,
                        )

        elif cmd == "goto":
            # Symbol completion for goto
            if len(words) == 1 or (len(words) == 2 and not text.endswith(" ")):
                prefix = words[1] if len(words) > 1 else ""
                for sym in self._symbols:
                    if sym.lower().startswith(prefix.lower()):
                        yield Completion(
                            sym,
                            start_position=-len(prefix) if prefix else 0,
                        )

        elif cmd == "asm":
            # Mnemonic completion for asm command
            if len(words) >= 1:
                # Get the last word being typed
                if text.endswith(" "):
                    prefix = ""
                else:
                    prefix = words[-1].lower()

                # Only complete if it looks like a mnemonic (start of instruction)
                # Check if we're at the start of an instruction
                last_part = text.split(";")[-1].strip()
                if not last_part or " " not in last_part:
                    for mnemonic in self._mnemonics:
                        if mnemonic.startswith(prefix):
                            yield Completion(
                                mnemonic,
                                start_position=-len(prefix) if prefix else 0,
                            )


def get_command_help(command: str) -> Optional[str]:
    """Get help text for a command.

    Args:
        command: Command name

    Returns:
        Help text or None
    """
    return COMMANDS.get(command.lower())


def get_all_commands() -> dict[str, str]:
    """Get all commands and descriptions.

    Returns:
        Dictionary of command -> description
    """
    return COMMANDS.copy()
