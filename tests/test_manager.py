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


def test_delete_entry_locked_raises(tmp_path: Path) -> None:
    """delete_entry before unlock raises RuntimeError."""
    vault = tmp_path / "vault.json"
    pm = PasswordManager(vault)
    pm.init_master("secret")
    with pytest.raises(RuntimeError):
        pm.delete_entry("github")


def test_add_entry_locked_raises(tmp_path: Path) -> None:
    """add_entry before unlock raises RuntimeError."""
    vault = tmp_path / "vault.json"
    pm = PasswordManager(vault)
    pm.init_master("secret")
    with pytest.raises(RuntimeError):
        pm.add_entry("github", "alice", "qwerty")


def test_add_list_get_delete(tmp_path: Path) -> None:
    """Test full CRUD cycle: add -> list -> get -> delete."""
    vault = tmp_path / "vault.json"
    pm = PasswordManager(vault)
    pm.init_master("secret")
    pm.unlock("secret")

    pm.add_entry("github", "alice", "qwerty")

    assert "github" in pm.list_entries()
    assert len(pm.list_entries()) == 1

    assert pm.get_entry("github") == ("alice", "qwerty")

    pm.delete_entry("github")
    assert pm.list_entries() == []


@pytest.mark.xfail(reason="Encryption not implemented yet")
def test_storage_does_not_contain_plaintext(tmp_path: Path) -> None:
    """Vault file must not contain passwords in plaintext (requires encryption)."""
    vault = tmp_path / "vault.json"
    pm = PasswordManager(vault)
    pm.init_master("secret")
    pm.unlock("secret")
    pm.add_entry("github", "alice", "qwerty")

    raw = vault.read_text(encoding="utf-8")
    assert "secret" not in raw
    assert "qwerty" not in raw