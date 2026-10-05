"""Regenerate aead_kbt.cbor: the draft's issuer_cwt.cbor, presented with one encrypted disclosure.

The first disclosure (inspector_license_number, 501) is encrypted with the
draft's AEAD key and nonce, so its sd_aead_encrypted_claims entry is
byte-identical to the draft's aead-claim-array.edn example. Two more are
disclosed in plaintext, as in kbt.cbor.

    .venv/bin/python tests/fixtures/draft-08/make_aead_kbt.py
"""

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from sd_cwt import cbor_utils
from sd_cwt.simple_api import SDCWTPresenter

HERE = Path(__file__).parent
AEAD_KEY = bytes.fromhex("a061c27a3273721e210d031863ad81b6")
AEAD_NONCE = bytes.fromhex("95d0040fe650e5baf51c907c")
AUDIENCE = "https://verifier.example/app"


def holder_key() -> dict:
    key = serialization.load_pem_private_key((HERE / "holder_privkey.pem").read_bytes(), None)
    public = key.public_key().public_numbers()
    return {
        1: 2,
        3: -7,
        -1: 1,
        -2: public.x.to_bytes(32, "big"),
        -3: public.y.to_bytes(32, "big"),
        -4: key.private_numbers().private_value.to_bytes(32, "big"),
    }


def main() -> None:
    from unittest import mock

    from sd_cwt import aead

    issued = (HERE / "issuer_cwt.cbor").read_bytes()
    disclosures = cbor_utils.get_tag_value(cbor_utils.decode(issued))[1][17]
    labels = {cbor_utils.decode(d)[-1]: d for d in disclosures}
    encrypted = [labels[501]]
    plaintext = [labels[1549560720], labels["region"]]

    with mock.patch.object(aead.os, "urandom", lambda n: AEAD_NONCE):
        kbt = SDCWTPresenter(holder_key()).create_presentation(
            sd_cwt=issued,
            disclosures=disclosures,
            selected_disclosures=plaintext,
            audience=AUDIENCE,
            encrypted_disclosures=encrypted,
            aead_key=AEAD_KEY,
        )
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "aead_kbt.cbor"
    out.write_bytes(kbt)
    print(f"wrote {out} ({len(kbt)} bytes)")


if __name__ == "__main__":
    main()
