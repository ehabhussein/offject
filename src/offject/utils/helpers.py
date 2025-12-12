"""Utility helper functions."""

from typing import Union


def parse_int(value: str) -> int:
    """Parse an integer from string, supporting hex (0x), binary (0b), and decimal.

    Args:
        value: String representation of integer

    Returns:
        Parsed integer value

    Raises:
        ValueError: If value cannot be parsed
    """
    value = value.strip()

    if not value:
        raise ValueError("Empty value")

    # Handle negative numbers
    negative = value.startswith("-")
    if negative:
        value = value[1:]

    # Auto-detect base
    if value.startswith("0x") or value.startswith("0X"):
        result = int(value, 16)
    elif value.startswith("0b") or value.startswith("0B"):
        result = int(value, 2)
    elif value.startswith("0o") or value.startswith("0O"):
        result = int(value, 8)
    else:
        # Try hex if it looks like hex (contains a-f)
        if any(c in value.lower() for c in "abcdef"):
            result = int(value, 16)
        else:
            result = int(value, 10)

    return -result if negative else result


def format_hex(data: bytes, uppercase: bool = True) -> str:
    """Format bytes as hex string.

    Args:
        data: Bytes to format
        uppercase: Use uppercase hex letters

    Returns:
        Hex string with spaces between bytes
    """
    fmt = "{:02X}" if uppercase else "{:02x}"
    return " ".join(fmt.format(b) for b in data)


def format_bytes(data: bytes) -> str:
    """Format bytes as continuous hex string without spaces.

    Args:
        data: Bytes to format

    Returns:
        Hex string without spaces
    """
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes.

    Args:
        hex_str: Hex string (with or without spaces, 0x prefix)

    Returns:
        Bytes object

    Raises:
        ValueError: If hex string is invalid
    """
    # Remove common prefixes and whitespace
    hex_str = hex_str.strip()
    hex_str = hex_str.replace(" ", "")
    hex_str = hex_str.replace("0x", "").replace("0X", "")
    hex_str = hex_str.replace("\\x", "")

    # Ensure even length
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str

    return bytes.fromhex(hex_str)


def format_size(size: int) -> str:
    """Format byte size in human-readable form.

    Args:
        size: Size in bytes

    Returns:
        Human-readable size string
    """
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}" if size != int(size) else f"{int(size)} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def is_printable_ascii(byte: int) -> bool:
    """Check if byte is printable ASCII.

    Args:
        byte: Byte value (0-255)

    Returns:
        True if printable ASCII
    """
    return 0x20 <= byte <= 0x7E


def bytes_to_ascii(data: bytes, placeholder: str = ".") -> str:
    """Convert bytes to ASCII representation.

    Args:
        data: Bytes to convert
        placeholder: Character to use for non-printable bytes

    Returns:
        ASCII string representation
    """
    return "".join(
        chr(b) if is_printable_ascii(b) else placeholder
        for b in data
    )


def align_address(address: int, alignment: int) -> int:
    """Align address to boundary.

    Args:
        address: Address to align
        alignment: Alignment boundary (must be power of 2)

    Returns:
        Aligned address
    """
    if alignment <= 0 or (alignment & (alignment - 1)) != 0:
        raise ValueError(f"Alignment must be power of 2, got {alignment}")
    return (address + alignment - 1) & ~(alignment - 1)


def chunks(data: bytes, size: int):
    """Yield chunks of data.

    Args:
        data: Data to chunk
        size: Chunk size

    Yields:
        Chunks of specified size
    """
    for i in range(0, len(data), size):
        yield data[i:i + size]
