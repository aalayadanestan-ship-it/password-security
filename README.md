# 🔐 Password Security Toolkit

A Python-based cybersecurity project designed to analyze password strength, generate secure passwords, and securely manage credentials using an encrypted password vault.

This project was developed for educational purposes to explore practical password security concepts and secure coding techniques.

---

## ✨ Features

### 🔍 Password Strength Checker

The password strength checker analyzes a password and provides:

- Password length
- Entropy estimation
- Strength score out of 100
- Strength rating
- Estimated brute-force cracking time
- Security issues
- Suggestions for improving the password

It can detect:

- Common passwords
- Short passwords
- Missing uppercase or lowercase characters
- Missing numbers
- Missing special characters
- Sequential patterns such as `abcd` and `4321`
- Keyboard patterns such as `qwerty` and `asdf`
- Repeated characters such as `aaaa`

---

### 🔑 Secure Password Generator

Generates cryptographically secure random passwords using Python's `secrets` module.

The generator supports:

- Uppercase letters
- Lowercase letters
- Numbers
- Special characters
- Custom password length

---

### 🗄️ Encrypted Password Vault

The toolkit also provides a command-line password vault.

Users can:

- Create a vault with a master password
- Add credentials
- Update existing credentials
- View stored credentials
- Delete credentials
- Generate and save secure passwords

---

## 🛠️ Technologies Used

- Python
- Cryptography
- Python `secrets`
- Regular Expressions (`re`)
- Command Line Interface (CLI)

---

## 📁 Project Structure

```text
password-security-toolkit/
│
├── main.py
├── generator.py
├── strength.py
├── vault.py
├── requirements.txt
└── README.md
```

---

## 🚀 How to Run

### 1. Open the project directory

```bash
cd password-security-toolkit
```

### 2. Install the required dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the application

```bash
python3 main.py
```

---

## 💻 Main Menu

When the application starts, the following options are available:

```text
==================================================
Password Security Toolkit
==================================================
1. Check password strength
2. Generate a secure password
3. Open encrypted vault
4. Exit
```

---

## 📦 Requirements

The project requires:

```text
cryptography>=41.0.0
```

Install it automatically using:

```bash
pip install -r requirements.txt
```

---

## 🔒 Security

The project uses secure random password generation instead of Python's standard `random` module.

Sensitive password input is hidden in the terminal using `getpass`.

> Do not upload real passwords, master passwords, encrypted vault files, API keys, or other sensitive information to GitHub.

---

## 🎯 Learning Objectives

This project helped me understand and practice:

- Password security concepts
- Password strength analysis
- Password entropy
- Secure random password generation
- Common password vulnerabilities
- Brute-force attack concepts
- Encrypted credential storage
- Python programming for cybersecurity

---

## ⚠️ Disclaimer

This project is created for **educational purposes only**.

It is intended to demonstrate password-security concepts and should not be considered a replacement for professionally audited password-management software.

---

## 👩‍💻 Author

**Aalaya Danestan**

GitHub: **aalayadanestan-ship-it**

---

⭐ If you found this project useful, feel free to star the repository!
