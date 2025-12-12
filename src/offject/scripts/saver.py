"""Patch script saver."""

from pathlib import Path
from typing import Optional

import yaml

from offject.scripts.loader import PatchScript, PatchEntry
from offject.core.patcher import Patch


class ScriptSaverError(Exception):
    """Exception for script saving errors."""
    pass


def save_script(script: PatchScript, file_path: Path | str) -> None:
    """Save a patch script to file.

    Args:
        script: PatchScript to save
        file_path: Output file path

    Raises:
        ScriptSaverError: If saving fails
    """
    path = Path(file_path) if isinstance(file_path, str) else file_path

    data = script_to_dict(script)

    try:
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(
                data,
                f,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )
    except IOError as e:
        raise ScriptSaverError(f"Failed to write file: {e}")


def save_script_to_string(script: PatchScript) -> str:
    """Save a patch script to string.

    Args:
        script: PatchScript to save

    Returns:
        YAML string
    """
    data = script_to_dict(script)
    return yaml.dump(
        data,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


def script_to_dict(script: PatchScript) -> dict:
    """Convert PatchScript to dictionary.

    Args:
        script: PatchScript object

    Returns:
        Dictionary suitable for YAML serialization
    """
    data = {
        "version": script.version,
        "architecture": script.architecture,
    }

    if script.mode:
        data["mode"] = script.mode

    if script.target_file:
        data["target"] = script.target_file

    if script.description:
        data["description"] = script.description

    # Convert patches
    patches = []
    for patch in script.patches:
        patch_data = {"offset": f"0x{patch.offset:X}"}

        if patch.asm:
            patch_data["asm"] = patch.asm
        elif patch.hex:
            patch_data["hex"] = patch.hex

        if patch.description:
            patch_data["description"] = patch.description

        patches.append(patch_data)

    data["patches"] = patches

    return data


def create_script_from_patches(
    patches: list[Patch],
    architecture: str = "x86",
    mode: str = "",
    target_file: str = "",
    description: str = "",
) -> PatchScript:
    """Create a PatchScript from a list of Patch objects.

    Args:
        patches: List of Patch objects from patcher
        architecture: Architecture name
        mode: Architecture mode
        target_file: Target file path
        description: Script description

    Returns:
        PatchScript object
    """
    script = PatchScript(
        version=1,
        architecture=architecture,
        mode=mode,
        target_file=target_file,
        description=description,
    )

    for patch in patches:
        # Store as hex since we have raw bytes
        script.patches.append(PatchEntry(
            offset=patch.offset,
            hex=patch.new_data.hex(),
            description=patch.description,
        ))

    return script


def create_script_from_assembly(
    patches: list[tuple[int, str, str]],
    architecture: str = "x86",
    mode: str = "",
    target_file: str = "",
    description: str = "",
) -> PatchScript:
    """Create a PatchScript from assembly strings.

    Args:
        patches: List of (offset, asm_code, description) tuples
        architecture: Architecture name
        mode: Architecture mode
        target_file: Target file path
        description: Script description

    Returns:
        PatchScript object
    """
    script = PatchScript(
        version=1,
        architecture=architecture,
        mode=mode,
        target_file=target_file,
        description=description,
    )

    for offset, asm, desc in patches:
        script.patches.append(PatchEntry(
            offset=offset,
            asm=asm,
            description=desc,
        ))

    return script
