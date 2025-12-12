"""Patch script loader."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from offject.utils.helpers import parse_int, hex_to_bytes


@dataclass
class PatchEntry:
    """Single patch entry from script."""

    offset: int
    asm: Optional[str] = None
    hex: Optional[str] = None
    description: str = ""

    def get_bytes(self) -> Optional[bytes]:
        """Get raw bytes if hex is specified.

        Returns:
            Bytes or None if using asm
        """
        if self.hex:
            return hex_to_bytes(self.hex)
        return None


@dataclass
class PatchScript:
    """Patch script definition."""

    version: int = 1
    architecture: str = "x86"
    mode: str = ""
    target_file: str = ""
    description: str = ""
    patches: list[PatchEntry] = field(default_factory=list)


class ScriptLoaderError(Exception):
    """Exception for script loading errors."""
    pass


def load_script(file_path: Path | str) -> PatchScript:
    """Load a patch script from file.

    Args:
        file_path: Path to YAML script file

    Returns:
        PatchScript object

    Raises:
        ScriptLoaderError: If loading fails
    """
    path = Path(file_path) if isinstance(file_path, str) else file_path

    if not path.exists():
        raise ScriptLoaderError(f"Script file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ScriptLoaderError(f"Invalid YAML: {e}")
    except IOError as e:
        raise ScriptLoaderError(f"Failed to read file: {e}")

    if not isinstance(data, dict):
        raise ScriptLoaderError("Script must be a YAML mapping")

    return parse_script(data)


def load_script_from_string(content: str) -> PatchScript:
    """Load a patch script from string.

    Args:
        content: YAML string

    Returns:
        PatchScript object
    """
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise ScriptLoaderError(f"Invalid YAML: {e}")

    if not isinstance(data, dict):
        raise ScriptLoaderError("Script must be a YAML mapping")

    return parse_script(data)


def parse_script(data: dict) -> PatchScript:
    """Parse script data into PatchScript.

    Args:
        data: Parsed YAML data

    Returns:
        PatchScript object
    """
    script = PatchScript(
        version=data.get("version", 1),
        architecture=data.get("architecture", data.get("arch", "x86")),
        mode=data.get("mode", ""),
        target_file=data.get("target", data.get("file", "")),
        description=data.get("description", ""),
    )

    # Parse patches
    patches_data = data.get("patches", [])
    if not isinstance(patches_data, list):
        raise ScriptLoaderError("'patches' must be a list")

    for i, patch_data in enumerate(patches_data):
        if not isinstance(patch_data, dict):
            raise ScriptLoaderError(f"Patch {i} must be a mapping")

        # Parse offset
        offset_raw = patch_data.get("offset")
        if offset_raw is None:
            raise ScriptLoaderError(f"Patch {i} missing 'offset'")

        try:
            if isinstance(offset_raw, int):
                offset = offset_raw
            else:
                offset = parse_int(str(offset_raw))
        except ValueError as e:
            raise ScriptLoaderError(f"Patch {i} invalid offset: {e}")

        # Must have either asm or hex
        asm = patch_data.get("asm")
        hex_data = patch_data.get("hex", patch_data.get("bytes"))

        if not asm and not hex_data:
            raise ScriptLoaderError(f"Patch {i} must have 'asm' or 'hex'")

        script.patches.append(PatchEntry(
            offset=offset,
            asm=asm,
            hex=hex_data,
            description=patch_data.get("description", ""),
        ))

    return script


def validate_script(script: PatchScript) -> list[str]:
    """Validate a patch script.

    Args:
        script: PatchScript to validate

    Returns:
        List of warning messages (empty if valid)
    """
    warnings = []

    if script.version != 1:
        warnings.append(f"Unknown script version: {script.version}")

    if not script.patches:
        warnings.append("Script has no patches")

    for i, patch in enumerate(script.patches):
        if patch.offset < 0:
            warnings.append(f"Patch {i}: negative offset")

        if patch.asm and patch.hex:
            warnings.append(f"Patch {i}: both 'asm' and 'hex' specified, 'asm' takes precedence")

    return warnings
