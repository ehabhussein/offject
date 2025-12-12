# Offject

Cross-platform multi-architecture binary patching tool.

Offject is an interactive binary patching tool that supports multiple CPU architectures. It allows you to assemble instructions, disassemble existing code, and patch binaries with an intuitive REPL interface.

## Features

- **Multi-architecture support**: x86 (16/32/64-bit), ARM/Thumb, ARM64, MIPS, PowerPC, SPARC
- **Binary format awareness**: Auto-detect and parse ELF, PE, and Mach-O files
- **Rich TUI**: Colored output, syntax highlighting, command completion
- **Disassembly preview**: See existing code before patching
- **Hex view**: View and analyze raw bytes
- **Undo/redo**: Full patch history with undo/redo support
- **Patch scripts**: Save and replay patches with YAML scripts
- **Cross-platform**: Works on Windows, Linux, and macOS

## Installation

```bash
pip install offject
```

Or install from source:

```bash
git clone https://github.com/ehabhussein/offject
cd offject
pip install -e .
```

### Dependencies

- Python 3.10+
- [keystone-engine](https://www.keystone-engine.org/) - Multi-architecture assembler
- [capstone](https://www.capstone-engine.org/) - Multi-architecture disassembler
- [LIEF](https://lief-project.github.io/) - Binary parsing library
- [rich](https://rich.readthedocs.io/) - Terminal formatting
- [prompt-toolkit](https://python-prompt-toolkit.readthedocs.io/) - Interactive CLI

## Quick Start

```bash
# Open a binary file
offject firmware.bin

# Open with specific architecture
offject -a arm_thumb firmware.bin

# Apply a patch script
offject -s patches.yaml firmware.bin -o patched.bin

# List supported architectures
offject --list-arch
```

## Interactive Commands

| Command | Description |
|---------|-------------|
| `arch [name]` | Show/set architecture |
| `asm <code>` | Assemble instruction(s) |
| `disasm [count]` | Disassemble at current offset |
| `goto <offset\|symbol>` | Jump to offset or symbol |
| `hex [size]` | Show hex dump |
| `patch` | Write assembled bytes |
| `info` | Show binary information |
| `sections` | List sections |
| `symbols [filter]` | List symbols |
| `history` | Show patch history |
| `undo` | Undo last patch |
| `redo` | Redo undone patch |
| `script load <file>` | Load patch script |
| `script save <file>` | Save patches as script |
| `save [file]` | Save patched binary |
| `open <file>` | Open a file |
| `clear` | Clear assembled buffer |
| `help [cmd]` | Show help |
| `exit` | Exit offject |

## Supported Architectures

| Name | Description |
|------|-------------|
| `x86` | Intel x86 32-bit |
| `x86_16` | Intel x86 16-bit |
| `x64` | Intel x86 64-bit |
| `arm` | ARM 32-bit |
| `arm_thumb` | ARM Thumb |
| `arm64` | ARM 64-bit (AArch64) |
| `mips32` | MIPS 32-bit Little Endian |
| `mips32be` | MIPS 32-bit Big Endian |
| `mips64` | MIPS 64-bit Little Endian |
| `mips64be` | MIPS 64-bit Big Endian |
| `ppc32` | PowerPC 32-bit |
| `ppc64` | PowerPC 64-bit Big Endian |
| `ppc64le` | PowerPC 64-bit Little Endian |
| `sparc32` | SPARC 32-bit |
| `sparc64` | SPARC 64-bit |

## Example Session

```
$ offject firmware.bin --arch arm_thumb

╭─ Offject v2.0 ─────────────────────────────────────────╮
│ File: firmware.bin  Arch: arm_thumb  Offset: 0x0       │
╰────────────────────────────────────────────────────────╯

offject[arm_thumb][0x0]> info
┌─────────────────────────────────────┐
│         Binary Information          │
├──────────────┬──────────────────────┤
│ File         │ firmware.bin         │
│ Format       │ ELF                  │
│ Size         │ 524,288 bytes        │
│ Architecture │ ARM                  │
│ Entry Point  │ 0x08001000           │
│ Sections     │ 5                    │
└──────────────┴──────────────────────┘

offject[arm_thumb][0x0]> goto 0x08001000
Offset: 0x08001000

offject[arm_thumb][0x8001000]> disasm 5
0x08001000: 10 b5        push  {r4, lr}
0x08001002: 04 46        mov   r4, r0
0x08001004: 00 f0 12 f8  bl    #0x08001234
0x08001008: 20 46        mov   r0, r4
0x0800100a: 10 bd        pop   {r4, pc}

offject[arm_thumb][0x8001000]> asm mov r0, #0; bx lr
Assembled: 00 20 70 47 (2 instruction(s), 4 bytes)

offject[arm_thumb][0x8001000]> patch
Patched 4 bytes at 0x8001000

offject[arm_thumb][0x8001000]> hex 32
08001000  00 20 70 47 00 f0 12 f8  04 46 20 46 10 bd 00 00  |. pG.....F F....|
08001010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

offject[arm_thumb][0x8001000]> save patched_firmware.bin
Saved to: patched_firmware.bin
```

## Patch Scripts

Patch scripts are YAML files that define a series of patches to apply:

```yaml
version: 1
architecture: arm_thumb
target: firmware.bin
description: Bypass authentication check

patches:
  - offset: 0x08001000
    asm: "mov r0, #1; bx lr"
    description: Always return true

  - offset: 0x08002000
    hex: "00bf00bf"
    description: NOP sled

  - offset: 0x08003000
    asm: "nop; nop; nop; nop"
```

Apply a script:

```bash
offject -s auth_bypass.yaml firmware.bin -o patched.bin
```

Or interactively:

```
offject[arm_thumb][0x0]> script load auth_bypass.yaml
Loaded script: Bypass authentication check
Applied 3/3 patches
```

## Python API

Offject can also be used as a library:

```python
from offject import Assembler, Disassembler, Patcher
from offject.binary import BinaryFile

# Assemble instructions
asm = Assembler("arm_thumb")
result = asm.assemble("mov r0, #0; bx lr")
print(f"Bytes: {result.hex}")  # 00 20 70 47

# Disassemble bytes
disasm = Disassembler("x64")
instructions = disasm.disassemble(b"\x55\x48\x89\xe5", 0x1000)
for insn in instructions:
    print(insn)  # 0x00001000: push rbp

# Patch a binary
patcher = Patcher("firmware.bin")
patcher.patch(0x1000, b"\x90\x90\x90\x90")
patcher.save("patched.bin")

# Parse binary info
binary = BinaryFile("program.exe")
print(f"Format: {binary.format}")
print(f"Entry: 0x{binary.info.entry_point:X}")
for section in binary.get_sections():
    print(f"  {section.name}: 0x{section.offset:X}")
```

## License

MIT License

## Credits

- [Keystone Engine](https://www.keystone-engine.org/) - Assembler framework
- [Capstone Engine](https://www.capstone-engine.org/) - Disassembler framework
- [LIEF](https://lief-project.github.io/) - Binary parsing library
