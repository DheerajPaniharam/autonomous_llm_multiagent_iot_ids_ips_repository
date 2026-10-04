"""
Async log file tailers for Suricata eve.json and Zeek conn.log.

tail_json_lines  — yields parsed JSON dicts from a newline-delimited JSON file
tail_tsv_lines   — yields parsed dicts from a Zeek TSV log file

Both functions:
  - Start from the end of the file (like `tail -f`)
  - Yield new records as they appear
  - Respect a stop_event for clean shutdown
  - Handle file rotation (file disappears and reappears)
  - Gracefully handle missing files (wait and retry)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from asyncio import Event
from pathlib import Path
from typing import AsyncIterator

logger = logging.getLogger(__name__)

# How long to sleep when no new data is available (seconds)
_POLL_INTERVAL = 0.1

# How long to wait before retrying a missing file (seconds)
_MISSING_FILE_RETRY = 5.0

# Zeek log column header prefix
_ZEEK_FIELDS_PREFIX = "#fields"
_ZEEK_SEPARATOR_PREFIX = "#separator"


async def tail_json_lines(
    path: str,
    stop_event: Event,
    poll_interval: float = _POLL_INTERVAL,
) -> AsyncIterator[dict]:
    """
    Async generator that tails a newline-delimited JSON file (e.g. Suricata eve.json).

    Yields parsed dicts for each new complete line appended to the file.
    Handles missing files, file rotation, and truncation.

    Args:
        path: Absolute or relative path to the JSON log file.
        stop_event: asyncio.Event — set this to stop the generator cleanly.
        poll_interval: Seconds to sleep between read attempts.
    """
    file_path = Path(path)
    file_obj = None
    last_inode: int | None = None

    logger.info("tail_json_lines: watching %s", path)

    while not stop_event.is_set():
        # Wait for file to exist
        if not file_path.exists():
            logger.debug("tail_json_lines: %s not found, retrying in %.1fs", path, _MISSING_FILE_RETRY)
            await asyncio.sleep(_MISSING_FILE_RETRY)
            continue

        try:
            current_inode = file_path.stat().st_ino
        except OSError:
            await asyncio.sleep(poll_interval)
            continue

        # Open or reopen on rotation
        if file_obj is None or current_inode != last_inode:
            if file_obj is not None:
                file_obj.close()
                logger.info("tail_json_lines: file rotated, reopening %s", path)
            try:
                file_obj = open(file_path, "r", encoding="utf-8", errors="replace")
                # Seek to end on first open so we only process new lines
                if last_inode is None:
                    file_obj.seek(0, os.SEEK_END)
                last_inode = current_inode
            except OSError as exc:
                logger.warning("tail_json_lines: cannot open %s: %s", path, exc)
                file_obj = None
                await asyncio.sleep(poll_interval)
                continue

        # Read available lines
        try:
            line = file_obj.readline()
        except OSError as exc:
            logger.warning("tail_json_lines: read error on %s: %s", path, exc)
            file_obj.close()
            file_obj = None
            last_inode = None
            await asyncio.sleep(poll_interval)
            continue

        if line:
            line = line.rstrip("\n")
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    logger.debug("tail_json_lines: skipping non-JSON line: %.80s", line)
        else:
            # No new data — yield control
            await asyncio.sleep(poll_interval)

    if file_obj is not None:
        file_obj.close()
    logger.info("tail_json_lines: stopped watching %s", path)


async def tail_tsv_lines(
    path: str,
    stop_event: Event,
    poll_interval: float = _POLL_INTERVAL,
) -> AsyncIterator[dict]:
    """
    Async generator that tails a Zeek TSV log file (e.g. conn.log).

    Parses the Zeek header block to extract column names and separator,
    then yields one dict per data line.

    Handles missing files, file rotation, and header re-parsing on rotation.

    Args:
        path: Absolute or relative path to the Zeek log file.
        stop_event: asyncio.Event — set this to stop the generator cleanly.
        poll_interval: Seconds to sleep between read attempts.
    """
    file_path = Path(path)
    file_obj = None
    last_inode: int | None = None
    columns: list[str] = []
    separator: str = "\t"

    logger.info("tail_tsv_lines: watching %s", path)

    while not stop_event.is_set():
        # Wait for file to exist
        if not file_path.exists():
            logger.debug("tail_tsv_lines: %s not found, retrying in %.1fs", path, _MISSING_FILE_RETRY)
            await asyncio.sleep(_MISSING_FILE_RETRY)
            continue

        try:
            current_inode = file_path.stat().st_ino
        except OSError:
            await asyncio.sleep(poll_interval)
            continue

        # Open or reopen on rotation
        if file_obj is None or current_inode != last_inode:
            if file_obj is not None:
                file_obj.close()
                logger.info("tail_tsv_lines: file rotated, reopening %s", path)
            try:
                file_obj = open(file_path, "r", encoding="utf-8", errors="replace")
                columns = []
                separator = "\t"
                # Parse header from the beginning
                columns, separator = _parse_zeek_header(file_obj)
                if not columns:
                    logger.warning("tail_tsv_lines: no #fields header found in %s", path)
                # Seek to end after parsing header so we only process new data lines
                file_obj.seek(0, os.SEEK_END)
                last_inode = current_inode
                logger.debug("tail_tsv_lines: parsed %d columns from %s", len(columns), path)
            except OSError as exc:
                logger.warning("tail_tsv_lines: cannot open %s: %s", path, exc)
                file_obj = None
                await asyncio.sleep(poll_interval)
                continue

        # Read available lines
        try:
            line = file_obj.readline()
        except OSError as exc:
            logger.warning("tail_tsv_lines: read error on %s: %s", path, exc)
            file_obj.close()
            file_obj = None
            last_inode = None
            columns = []
            await asyncio.sleep(poll_interval)
            continue

        if line:
            line = line.rstrip("\n")
            # Skip comment/header lines that appear mid-file (e.g. on rotation)
            if line.startswith("#"):
                # Re-parse separator/fields if we see a new header block
                if line.startswith(_ZEEK_SEPARATOR_PREFIX):
                    separator = _decode_zeek_separator(line)
                elif line.startswith(_ZEEK_FIELDS_PREFIX):
                    columns = line.split(separator)[1:]
            elif line and columns:
                record = _parse_zeek_data_line(line, columns, separator)
                if record is not None:
                    yield record
        else:
            # No new data — yield control
            await asyncio.sleep(poll_interval)

    if file_obj is not None:
        file_obj.close()
    logger.info("tail_tsv_lines: stopped watching %s", path)


# ---------------------------------------------------------------------------
# Zeek header parsing helpers
# ---------------------------------------------------------------------------

def _decode_zeek_separator(line: str) -> str:
    """
    Decode a Zeek #separator line.
    Zeek encodes the separator as e.g. '#separator \\x09' for tab.
    """
    parts = line.split(" ", 1)
    if len(parts) < 2:
        return "\t"
    raw = parts[1].strip()
    # Handle common escape sequences
    if raw.startswith("\\x"):
        try:
            return bytes.fromhex(raw[2:]).decode("ascii")
        except ValueError:
            pass
    return raw or "\t"


def _parse_zeek_header(file_obj) -> tuple[list[str], str]:
    """
    Read the Zeek header block from the beginning of an open file.
    Returns (columns, separator).
    """
    columns: list[str] = []
    separator = "\t"
    start_pos = file_obj.tell()
    file_obj.seek(0)

    for line in file_obj:
        line = line.rstrip("\n")
        if not line.startswith("#"):
            break
        if line.startswith(_ZEEK_SEPARATOR_PREFIX):
            separator = _decode_zeek_separator(line)
        elif line.startswith(_ZEEK_FIELDS_PREFIX):
            # e.g. "#fields\tts\tuid\tid.orig_h\t..."
            parts = line.split(separator)
            columns = parts[1:]  # skip the "#fields" token

    return columns, separator


def _parse_zeek_data_line(
    line: str, columns: list[str], separator: str
) -> dict | None:
    """Parse a single Zeek data line into a dict using the given columns."""
    parts = line.split(separator)
    if len(parts) != len(columns):
        return None
    record: dict[str, str] = {}
    for col, val in zip(columns, parts):
        # Replace Zeek's '-' (missing value) with empty string
        record[col] = "" if val == "-" else val
    return record
