"""Tests for the command-line argument parsing (the network paths are integration)."""

from __future__ import annotations

import argparse

import pytest

from torquests import cli
from torquests.cli import _build_parser, main


def test_get_parses_url_headers_and_output() -> None:
    args = _build_parser().parse_args(
        ["get", "http://example.onion", "-H", "User-Agent", "curl/8", "-o", "out.html"]
    )
    assert args.command == "get"
    assert args.url == "http://example.onion"
    assert args.header == [["User-Agent", "curl/8"]]
    assert args.output == "out.html"


def test_socks_defaults() -> None:
    args = _build_parser().parse_args(["socks"])
    assert args.command == "socks"
    assert args.host == "127.0.0.1"
    assert args.port == 9050


def test_a_command_is_required() -> None:
    with pytest.raises(SystemExit):
        _build_parser().parse_args([])


def test_ctrl_c_during_a_command_halts_cleanly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A Ctrl-C mid-command (e.g. during bootstrap) exits 130, not a traceback."""

    def _interrupt(_args: argparse.Namespace) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_cmd_ip", _interrupt)
    try:
        code = main(["ip"])
    except KeyboardInterrupt:
        pytest.fail("main() let KeyboardInterrupt reach the terminal instead of halting")
    assert code == 130  # 128 + SIGINT(2), the shell convention for a Ctrl-C abort
    assert "interrupted" in capsys.readouterr().err


def test_ctrl_c_stops_the_socks_proxy_cleanly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Ctrl-C is the documented way to stop the proxy, so it exits 0, not an error."""

    def _interrupt(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("torquests.socks.serve", _interrupt)
    code = main(["socks"])
    assert code == 0
    assert "stopped" in capsys.readouterr().err


def test_a_command_failure_still_exits_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def _fail(_args: argparse.Namespace) -> int:
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "_cmd_get", _fail)
    code = main(["get", "http://example.onion"])
    assert code == 1
    assert "error: boom" in capsys.readouterr().err
