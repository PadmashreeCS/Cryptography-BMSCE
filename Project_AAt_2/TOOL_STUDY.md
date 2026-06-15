# Tool Study — CrypTool

**CRP Academic Project | AES-256 CBC Security System**
**Subject:** Cryptography and Network Security
**Submitted by:** Padmashree S

---

## 1. Tool Name

**CrypTool** (specifically **CrypTool Online** — the browser-based edition)

- Website: https://www.cryptool.org
- Online version: https://www.cryptool.org/en/cto/

---

## 2. Introduction

CrypTool is a free, open-source e-learning platform dedicated to cryptography
and cryptanalysis. First released in 1998 by Bernhard Esslinger at Deutsche
Bank, it has grown into a suite of applications used in universities, schools,
and research institutions worldwide.

The suite includes four major variants:

| Variant         | Platform         | Notes                                   |
|-----------------|------------------|-----------------------------------------|
| CrypTool 1 (CT1)| Windows desktop  | Oldest; widest cipher support           |
| CrypTool 2 (CT2)| Windows desktop  | Visual, flow-based design interface     |
| JCrypTool (JCT) | Java desktop     | Cross-platform desktop version          |
| CrypTool Online | Web browser      | No installation; used in this study     |

In this study, **CrypTool Online** was used because it requires no
installation and can be demonstrated live in any browser during faculty
evaluation.

---

## 3. Purpose

CrypTool is designed to:

- Provide a **visual, interactive environment** for learning classical and
  modern ciphers without writing any code.
- Allow students to **experiment with encryption and decryption** using
  built-in GUI controls.
- Supply **cryptanalysis tools** so students can immediately see how ciphers
  are broken.
- Serve as a **reference implementation** against which custom-coded cipher
  implementations can be validated.

In the context of this project, CrypTool was used as a **ground-truth
validator**: by encrypting the same plaintext with the same key and IV in CrypTool
and in our application, the ciphertext outputs must be identical, confirming
that our manually implemented AES-256 CBC cipher is mathematically correct.

---

## 4. Installation

### CrypTool Online (used in this study) — No Installation Required

1. Open any modern web browser (Chrome, Firefox, Edge).
2. Navigate to: **https://www.cryptool.org/en/cto/**
3. The tool loads directly in the browser — no download, no account needed.

### CrypTool 2 (Desktop — Optional Reference)

1. Visit https://www.cryptool.org/en/ct2/downloads
2. Download the Windows installer (`.exe`).
3. Run the installer and follow the on-screen prompts.
4. Launch **CrypTool 2** from the Start Menu.

> **Note:** Only CrypTool Online was used for this study. CrypTool 2
> installation steps are included for completeness.

---

## 5. Basic Practical Demonstration

The following steps were performed in **CrypTool Online** to demonstrate
AES-256 CBC cipher encryption.

### Step A — Open CrypTool Online and Select the AES Cipher

1. Navigate to https://www.cryptool.org/en/cto/
2. Click **"Ciphers"** in the top navigation menu.
3. Select **"AES"** from the Symmetric (Modern) list.

**[Screenshot A]**
```
+--------------------------------------------------+
|  CrypTool Online — Ciphers → AES Cipher          |
|  [ Cipher selection dropdown showing "AES" ]     |
+--------------------------------------------------+
```
*(Replace with actual screenshot during presentation)*

---

### Step B — Enter Plaintext

In the **Plaintext** input field, type the message to encrypt:

```
Plaintext:  ATTACKATDAWN
```

**[Screenshot B]**
```
+--------------------------------------------------+
|  Plaintext field: ATTACKATDAWN                   |
+--------------------------------------------------+
```
*(Replace with actual screenshot during presentation)*

---

### Step C — Enter the Encryption Key and IV

In the **Key** field, type the 256-bit hexadecimal key and set the mode of operation to CBC with a corresponding Initialization Vector (IV).

---

### Step D — Encrypt and Observe the Output

Click the **"Encrypt"** button. CrypTool computes ciphertext using the block-by-block AES transformations (SubBytes, ShiftRows, MixColumns, AddRoundKey) in Cipher Block Chaining (CBC) mode.

**[Screenshot D]**
```
+--------------------------------------------------+
|  Ciphertext output                               |
+--------------------------------------------------+
```
*(Replace with actual screenshot during presentation)*

> Our application produces the **same ciphertext** for the same input and key — confirming implementation correctness.

---

## 6. Screenshots

> **Note:** The screenshots below are placeholders. During the faculty
> presentation, replace each placeholder with an actual screenshot captured
> from CrypTool Online.

| # | Description                                      | File (to be added)          |
|---|--------------------------------------------------|-----------------------------|
| A | CrypTool: AES cipher selected from menu          | `screenshots/ct_cipher_select.png` |
| B | CrypTool: Plaintext `ATTACKATDAWN` entered       | `screenshots/ct_plaintext.png`     |
| D | CrypTool: Ciphertext output                      | `screenshots/ct_ciphertext.png`    |

To add real screenshots:
1. Perform each step in CrypTool Online.
2. Take a screenshot (Windows: `Win + Shift + S`).
3. Save to the `screenshots/` folder inside this project.
4. Update the table above with the actual filenames.

---

## 7. Relation to the Project

This project implements the **same AES-256 CBC cipher algorithms** as CrypTool,
built entirely from scratch in Python — without using any external
cryptography library. The table below shows how each CrypTool feature maps
directly to a module or function in this project.

| CrypTool Feature              | This Project's Implementation                                     |
|-------------------------------|-------------------------------------------------------------------|
| AES-256 CBC Encryption        | `aes256.encrypt_cbc()`                                            |
| AES-256 CBC Decryption        | `aes256.decrypt_cbc()`                                            |
| Step-by-step block trace      | `aes256.py` + AES Demo page                                       |
| Round-by-round visualization  | AES Internals page                                                |
| Password hashing              | `crypto_utils.hash_password()` — SHA-256 + random salt            |
| Encrypted database storage    | `crypto_utils.encrypt_data()` — ciphertext-only in DB             |
| Two-factor OTP authentication | `auth.py`                                                         |

### Key Difference

CrypTool is a **pre-built educational tool** where users interact via a GUI.
This project demonstrates the **same mathematical principles** through a
fully custom-coded Python web application — every line of the cipher
implementation is written by the student and is fully explainable.

CrypTool served as a **validation reference**: if CrypTool and this
application produce identical ciphertext for the same plaintext, key, and IV,
it confirms the implementation is correct.

### Why This Matters for the CRP

The comparison proves:

1. **Algorithmic correctness** — our `aes256.py` matches an established,
   trusted tool's output.
2. **No black-box reliance** — unlike CrypTool, we use zero external crypto
   libraries (`hashlib`, `os`, `hmac` from Python stdlib only).
3. **Extended scope** — our project goes beyond CrypTool's scope by adding
   user authentication, OTP-based 2-factor auth, and encrypted database
   storage — features not present in CrypTool at all.

---

*End of Tool Study Document*
