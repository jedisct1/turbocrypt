# Cryptography

[Back to the main README](../README.md)

TurboCrypt uses a random 128-bit master key. It derives a separate key for
each purpose, encrypts every file independently, and optionally encrypts each
filename component.

| Purpose                                | Construction                                     |
| -------------------------------------- | ------------------------------------------------ |
| Key derivation and contexts            | TurboSHAKE128                                    |
| File encryption                        | AEGIS-128X2 with a 128-bit tag                   |
| Header and Git metadata authentication | AEGISMAC-128X2 with a 128-bit output             |
| Filename encryption                    | HCTR2 with AES-128, followed by base84 encoding  |
| Password-protected key files           | Argon2id, then an XOR mask and password verifier |

## Keys and contexts

`keygen` obtains 16 random bytes from the operating system. This master key is
expanded into six 16-byte keys with TurboSHAKE128. Using `||` for
concatenation, the input is:

```text
master_key || "turbocrypt" || ("-" || context, when context is non-empty)
```

TurboSHAKE128 produces 96 bytes, split in this order:

```text
header MAC key || file encryption key || filename key ||
plaintext fingerprint key || ciphertext identity key || key identity key
```

An absent context and an empty context are equivalent. Any other context
produces a different set of derived keys, so the same master key and the exact
same context are required for decryption. A context is domain separation, not
a password-strengthening function or an additional authentication factor.

## File contents

Each file is encrypted as one AEGIS-128X2 authenticated-encryption message.
TurboCrypt generates a fresh random 16-byte nonce and writes this format:

```text
offset       length       value
0            16 bytes     random nonce
16           16 bytes     header MAC
32           plaintext    ciphertext
end - 16     16 bytes     AEGIS authentication tag
```

The encrypted file is therefore exactly 48 bytes longer than the plaintext.
The header MAC is:

```text
AEGISMAC-128X2(header_mac_key, zero_nonce, "TC01" || file_nonce)
```

The MAC uses its all-zero 16-byte nonce. `TC01` separates version 1 of this
format from other uses of the MAC. The header MAC lets TurboCrypt reject a
wrong key or context without processing the whole file. It does not
authenticate the ciphertext body: `verify --quick` checks only this MAC,
whereas normal decryption and `verify` check the AEGIS tag over the complete
ciphertext.

Ordinary `encrypt` and `decrypt` operations use empty associated data, so an
encrypted file can be moved or renamed. The Git integration instead supplies
the plaintext-relative path as AEGIS associated data. This binds a Git store
entry to its path and detects moved or swapped ciphertexts.

Because encryption uses a fresh nonce, encrypting the same contents twice
normally produces different files. Authentication is whole-file rather than
chunked: changing the ciphertext or tag makes the entire file fail
authentication.

## Filename encryption

With `--encrypted-filenames`, TurboCrypt handles each path component
separately. It pads names shorter than 16 bytes with zero bytes, applies HCTR2
with AES-128 and an empty tweak, and base84-encodes the result.

Base84 makes the ciphertext usable as a filename on Linux, macOS, and Windows.

HCTR2 is length-preserving and deterministic for a fixed key and tweak.
Consequently, equal names under the same key and context have equal encrypted
names, including when they occur in different directories. The encoded name
also reveals the padded name length: names up to 16 bytes are indistinguishable
by length, while longer lengths remain visible. Directory structure, entry
counts, and file sizes are not hidden.

Filename ciphertexts have no separate authentication tag. Decryption checks
that the base84 representation and zero padding are canonical and that the
result is a safe path component.

In the Git integration, the path binding on the file contents
provides authentication against moving or swapping store entries.

## Password-protected key files

A plain key file contains the raw 16-byte master key. Password protection does
not change that key or re-encrypt any data. It changes the key-file encoding to
21 bytes.

TurboCrypt derives 20 bytes `D` with Argon2id using the password, the fixed
salt `"turbocrypt"`, two passes, 64 MiB of memory, and one lane. It then stores:

```text
0x01 || (master_key XOR D[0..16]) || D[16..20]
```

The final four bytes are a password verifier. They allow TurboCrypt to reject
a wrong password before using the recovered master key.

The fixed salt means that the password-derived value and verifier are the same
whenever the same password is reused. Anyone who obtains a protected key file
can test password guesses offline. Argon2id makes each guess more expensive,
but protection still depends on the strength of the password. Use a long,
unique password and protect backups of the key file.

## Git metadata

The Git integration uses AEGISMAC-128X2, with its all-zero nonce, under three
additional derived keys:

- The key identity is the MAC of the string `"key id"`. It names the key's
  public directory under `.enc/` without publishing the master key.

- A keyed fingerprint of each plaintext lets the local sync state detect
  changes without storing an unkeyed hash that could confirm guesses about
  the file.

- A keyed identity of the complete encrypted file detects any ciphertext
  change when comparing the store with the local sync state.

These values are each 16 bytes. They support synchronization; they do not hide
the Git metadata described in [Private files in Git](git.md#metadata-and-limitations),
and they do not prevent rollback of a complete repository state.

## Specifications

- [The AEGIS family of authenticated encryption algorithms](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/)
- [RFC 9861: KangarooTwelve and TurboSHAKE](https://www.rfc-editor.org/rfc/rfc9861.html)
- [Length-preserving encryption with HCTR2](https://eprint.iacr.org/2021/1441)
- [FIPS 197: Advanced Encryption Standard](https://csrc.nist.gov/pubs/fips/197/final)
- [RFC 9106: Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)
