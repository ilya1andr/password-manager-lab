"""Command-line interface for PasswordManager."""

import argparse
import getpass
from pathlib import Path

from password_manager.manager import PasswordManager


def main() -> None:
    """Entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Менеджер паролей."
    )

    parser.add_argument(
        "--init",
        action="store_true",
        help="Создать новое хранилище с мастер-паролем"
    )
    parser.add_argument(
        "--unlock",
        action="store_true",
        help="Войти в хранилище"
    )
    parser.add_argument(
        "--generate",
        action="store_true",
        help="Сгенерировать пароль"
    )

    args = parser.parse_args()

    if not (args.init or args.unlock or args.generate):
        parser.print_help()
        return


    vault_path = Path("vault.json")
    pm = PasswordManager(vault_path)

    if args.init:
        print("Создание нового хранилища...")
        password = getpass.getpass("Придумайте мастер-пароль: ")
        password_confirm = getpass.getpass("Повторите мастер-пароль: ")

        if password != password_confirm:
            print("Пароли не совпадают.")
            return

        if len(password) < 4:
            print("Ошибка: пароль слишком короткий (минимум 4 символа).")
            return

        try:
            pm.init_master(password)
            print("Готово! Хранилище создано.")
        except RuntimeError as e:
            print(f"Ошибка: {e}")

    elif args.unlock:
        print("Вход в хранилище...")
        password = getpass.getpass("Введите пароль: ")

        try:
            success = pm.unlock(password)
            if success:
                print("Хранилище разблокировано.")
                interactive_menu(pm)
            else:
                print("Ошибка: неверный пароль.")
        except RuntimeError as e:
            print(f"Ошибка: {e}")
        except KeyError:
            print("Ошибка: хранилище не найдено. Сначала выполните --init.")

    elif args.generate:
        pwd = pm.generate_password()
        print(f"Сгенерированный пароль: {pwd}")


def interactive_menu(pm: PasswordManager) -> None:
    """Run the interactive menu after unlocking."""
    print("\nДоступные команды: add, list, get <имя>, delete <имя>, generate, exit")
    while True:
        command = input("\n> ").strip().split()
        if not command:
            continue

        cmd = command[0].lower()

        if cmd == "exit":
            print("Выход.")
            break

        elif cmd == "add":
            name = input("Имя сервиса: ")
            login = input("Логин: ")
            password = getpass.getpass("Пароль: ")
            try:
                pm.add_entry(name, login, password)
                print(f"Запись {name} добавлена.")
            except Exception  as e:
                print(f"Ошибка: {e}")

        elif cmd == "list":
            try:
                entries = pm.list_entries()
                if not  entries:
                    print("В хранилище нет записей.")
                else:
                    for name in entries:
                        print(name)
            except Exception as e:
                print(f"Ошибка: {e}")

        elif cmd == "get":
            if len(command) < 2:
                print("Формат ввода: get <имя>")
                continue
            name = command[1]
            try:
                login, pwd = pm.get_entry(name)
                print(f"Сервис: {name}")
                print(f"Логин:  {login}")
                print(f"Пароль: {pwd}")
            except KeyError:
                print(f"Запись '{name}' не найдена.")
            except Exception as e:
                print(f"Ошибка: {e}")

        elif cmd == "delete":
            if len(command) < 2:
                print("Формат ввода: delete <имя>")
                continue
            name = command[1]
            try:
                pm.delete_entry(name)
                print(f"Запись '{name}' удалена.")
            except KeyError:
                print(f"Запись '{name}' не найдена.")
            except Exception as e:
                print(f"Ошибка: {e}")

        elif cmd == "generate":
            print(f"Новый пароль: {pm.generate_password()}")

        else:
            print("Неизвестная команда. Доступно: add, list, get <имя>, "
                  "delete <имя>, generate, exit")



if __name__ == "__main__":
    main()
