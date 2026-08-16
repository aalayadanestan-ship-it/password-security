"""
main.py
CLI for the Password Strength Checker & Encrypted Manager.

Run:  python main.py
"""

import getpass
import os
import sys

from strength import analyze_password, estimate_crack_time
from generator import generate_password
from vault import Vault, VaultError

VAULT_PATH = os.path.join(os.path.dirname(__file__), "vault.enc")


def print_header(title: str) -> None:
    print("\n" + "=" * 50)
    print(title)
    print("=" * 50)


def check_strength_flow() -> None:
    print_header("Password Strength Checker")
    pw = getpass.getpass("Enter a password to analyze (input hidden): ")
    if not pw:
        print("No password entered.")
        return

    report = analyze_password(pw)
    print(f"\nLength:         {report['length']}")
    print(f"Entropy:        {report['entropy_bits']} bits")
    print(f"Score:          {report['score']}/100")
    print(f"Rating:         {report['rating']}")
    print(f"Est. crack time (offline attack): {estimate_crack_time(report['entropy_bits'])}")

    if report["issues"]:
        print("\nIssues found:")
        for issue in report["issues"]:
            print(f"  - {issue}")
    else:
        print("\nNo issues detected.")

    if report["suggestions"]:
        print("\nSuggestions:")
        for s in report["suggestions"]:
            print(f"  - {s}")


def generate_password_flow() -> None:
    print_header("Secure Password Generator")
    try:
        length = int(input("Length (default 16): ") or 16)
    except ValueError:
        length = 16
    pw = generate_password(length=length)
    report = analyze_password(pw)
    print(f"\nGenerated password: {pw}")
    print(f"Strength: {report['rating']} ({report['score']}/100, {report['entropy_bits']} bits entropy)")


def get_vault() -> Vault:
    return Vault(VAULT_PATH)


def vault_setup_flow(vault: Vault) -> None:
    print_header("Create New Vault")
    pw1 = getpass.getpass("Set a master password: ")
    pw2 = getpass.getpass("Confirm master password: ")
    if pw1 != pw2:
        print("Passwords do not match.")
        return
    report = analyze_password(pw1)
    if report["rating"] in ("Weak", "Very Weak"):
        print(f"\nWarning: your master password is rated '{report['rating']}'.")
        confirm = input("Use it anyway? (y/N): ").strip().lower()
        if confirm != "y":
            print("Vault creation cancelled.")
            return
    vault.create(pw1)
    print(f"\nVault created at {vault.path}")


def vault_menu(vault: Vault) -> None:
    master = getpass.getpass("Master password: ")
    try:
        services = vault.list_services(master)
    except VaultError as e:
        print(f"Error: {e}")
        return

    while True:
        print_header("Vault Menu")
        print(f"Stored services: {', '.join(services) if services else '(none)'}")
        print("1. Add / update entry")
        print("2. View entry")
        print("3. Delete entry")
        print("4. Generate + save new entry")
        print("5. Back to main menu")
        choice = input("Choose an option: ").strip()

        try:
            if choice == "1":
                service = input("Service name: ").strip()
                username = input("Username: ").strip()
                pw = getpass.getpass("Password: ")
                vault.add_entry(master, service, username, pw)
                print(f"Saved entry for '{service}'.")
            elif choice == "2":
                service = input("Service name: ").strip()
                entry = vault.get_entry(master, service)
                print(f"Username: {entry['username']}")
                print(f"Password: {entry['password']}")
            elif choice == "3":
                service = input("Service name: ").strip()
                vault.delete_entry(master, service)
                print(f"Deleted entry for '{service}'.")
            elif choice == "4":
                service = input("Service name: ").strip()
                username = input("Username: ").strip()
                length = int(input("Password length (default 16): ") or 16)
                pw = generate_password(length=length)
                vault.add_entry(master, service, username, pw)
                print(f"Generated and saved password for '{service}': {pw}")
            elif choice == "5":
                break
            else:
                print("Invalid option.")
        except VaultError as e:
            print(f"Error: {e}")

        services = vault.list_services(master)


def main() -> None:
    vault = get_vault()
    while True:
        print_header("Password Security Toolkit")
        print("1. Check password strength")
        print("2. Generate a secure password")
        print("3. Open encrypted vault" + (" (create new)" if not vault.exists() else ""))
        print("4. Exit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            check_strength_flow()
        elif choice == "2":
            generate_password_flow()
        elif choice == "3":
            if not vault.exists():
                vault_setup_flow(vault)
            else:
                vault_menu(vault)
        elif choice == "4":
            print("Goodbye.")
            sys.exit(0)
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
