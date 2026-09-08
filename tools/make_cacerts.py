"""Build the CA directory an Android title expects at /system/etc/security/cacerts.

A native title that speaks HTTPS does not carry its own trust anchors: it points
OpenSSL at Android's hashed CA directory and lets it find the issuer by name.
The lookup is a stat of <hash>.<n>, so a directory that is merely absent fails
the same way an untrusted certificate does -- the connection is abandoned before
the handshake writes a byte, and the title reports that it has no internet.

The hash is OpenSSL's own, and there are two of them: X509_NAME_hash (SHA1, what
OpenSSL 1.0 and later use) and X509_NAME_hash_old (MD5, which Android's own
store was built with). Which one a title's OpenSSL asks for depends on how it
was built, so both names are written for every certificate. They are hard links
to the same bytes in spirit and copies in fact; the whole store is under a
megabyte.

Certificates come from the host's own root store, so this trusts exactly what
the host already trusts and ships no CA bundle of its own.
"""
import pathlib
import ssl
import subprocess
import sys


def pem_of(der: bytes) -> str:
    body = ssl.DER_cert_to_PEM_cert(der)
    return body


def hashes(pem: str) -> list[str]:
    out = []
    for flag in ("-subject_hash", "-subject_hash_old"):
        r = subprocess.run(["openssl", "x509", "-noout", flag],
                           input=pem, capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            out.append(r.stdout.strip())
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: make_cacerts.py <dir>", file=sys.stderr)
        return 2
    target = pathlib.Path(sys.argv[1])
    target.mkdir(parents=True, exist_ok=True)
    written = 0
    seen: dict[str, int] = {}
    for der, _enc, _trust in ssl.enum_certificates("ROOT"):
        pem = pem_of(der)
        for h in hashes(pem):
            # Several certificates can share a subject hash; OpenSSL walks
            # .0, .1, .2 until it runs out, so the suffix has to count up
            # rather than overwrite.
            n = seen.get(h, 0)
            seen[h] = n + 1
            (target / f"{h}.{n}").write_text(pem)
            written += 1
    print(f"wrote {written} files to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
