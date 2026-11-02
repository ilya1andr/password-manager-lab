"""Tests for PasswordManager."""

from pathlib import Path

import pytest

from password_manager.manager import PasswordManager


def test_unlock_correct_password(tmp_path: Path) -> None:
    """Correct master password unlocks vault."""
    vault = tmp_path / "vault.json"
    pm = PasswordManager(vault)
    pm.init_master("secret")
    assert pm.unlock("secret") is True


def test_unlock_wrong_password(tmp_path: Path) -> None:
    """Wrong master password does not unlock vault."""
    vault = tmp_path / "vault.json"
    pm = PasswordManager(vault)
    pm.init_master("secret")
    assert pm.unlock("wrong") is False


def test_init_master_twice_raises(tmp_path: Path) -> None:
    """Second init_master raises RuntimeError."""
    vault = tmp_path / "vault.json"
    pm = PasswordManager(vault)
    pm.init_master("secret")
    with pytest.raises(RuntimeError):
        pm.init_master("another")
