"""Verify a test secp256k1 private key without committing key material.

Set both CRYSCOUT_TEST_PRIVATE_KEY and CRYSCOUT_TEST_ADDRESS in the local
environment before running this script. Use synthetic/test-only values.
"""

import hashlib
import os
import sys

import base58
import ecdsa


def privkey_to_address(privkey_hex, compressed=True):
    value = privkey_hex.removeprefix("0x")
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(value), curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()

    if compressed:
        prefix = b"\x02" if vk.pubkey.point.y() % 2 == 0 else b"\x03"
        public_key = prefix + vk.to_string()[:32]
    else:
        public_key = b"\x04" + vk.to_string()

    sha256 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new("ripemd160", sha256).digest()
    versioned_payload = b"\x00" + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    return base58.b58encode(versioned_payload + checksum).decode()


def main():
    private_key = os.getenv("CRYSCOUT_TEST_PRIVATE_KEY")
    target_address = os.getenv("CRYSCOUT_TEST_ADDRESS")

    if not private_key or not target_address:
        sys.exit(
            "Set CRYSCOUT_TEST_PRIVATE_KEY and CRYSCOUT_TEST_ADDRESS to "
            "synthetic/test-only values before running this script."
        )

    compressed = privkey_to_address(private_key, compressed=True)
    uncompressed = privkey_to_address(private_key, compressed=False)

    print(f"Compressed:   {compressed}")
    print(f"Uncompressed: {uncompressed}")
    print("Match:", target_address in (compressed, uncompressed))


if __name__ == "__main__":
    main()
