from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from qmu import cli
from qmu.commands import qmp_cmds
from qmu.instance import QMUError, VMInstance


def test_parse_nm_posix_text_symbol():
    assert qmp_cmds._parse_nm_text(
        "startup_64 T ffffffff81000000\n"
        "_text T ffffffff81000000\n"
        "_stext T ffffffff81000100\n"
    ) == 0xFFFFFFFF81000000


def test_parse_nm_ignores_nearby_symbol_names():
    assert qmp_cmds._parse_nm_text(
        "_stext T 1000\n_text T 2000\n_text_end T 3000\n"
    ) == 0x2000


@pytest.mark.parametrize(
    ("output", "fragment"),
    [
        ("_stext T 1000\n", "missing _text"),
        ("_text T 1000\n_text T 2000\n", "multiple _text"),
        ("_text T not-hex\n", "invalid _text address"),
        ("_text T 0\n", "zero _text address"),
    ],
)
def test_parse_nm_rejects_unusable_text(output, fragment):
    with pytest.raises(QMUError, match=fragment):
        qmp_cmds._parse_nm_text(output)


def test_parse_kallsyms_text_symbol():
    assert qmp_cmds._parse_kallsyms_text(
        "ffffffff95200000 T _text\n"
    ) == 0xFFFFFFFF95200000


@pytest.mark.parametrize(
    ("output", "fragment"),
    [
        ("ffffffff95200000 T _stext\n", "missing _text"),
        (
            "ffffffff95200000 T _text\nffffffff95400000 T _text\n",
            "multiple _text",
        ),
        ("not-hex T _text\n", "invalid _text address"),
        ("0000000000000000 T _text\n", "restricted /proc/kallsyms"),
    ],
)
def test_parse_kallsyms_rejects_unusable_text(output, fragment):
    with pytest.raises(QMUError, match=fragment):
        qmp_cmds._parse_kallsyms_text(output)


def test_format_hex_supports_zero_positive_and_negative_values():
    assert qmp_cmds._format_hex(0) == "0x0"
    assert qmp_cmds._format_hex(0x14000000) == "0x14000000"
    assert qmp_cmds._format_hex(-0x200000) == "-0x200000"
