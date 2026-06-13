from os import urandom
from ecdsa import SigningKey, VerifyingKey, ECDH, SECP256k1

from .. import constants
from ..card_interface import CardInterface
from ..crypto.aes import aes_cbc_encrypt
from ..crypto.generate_pairing_token import generate_pairing_token
from ..exceptions import NotSelectedError
from ..preconditions import require_selected


@require_selected
def init(
    card: CardInterface,
    pin: str | bytes,
    puk: str | bytes,
    pairing_secret: str | bytes,
    duress_pin: str | bytes | None = None,
    pin_limit: int | None = None,
    puk_limit: int | None = None
) -> None:
    '''
    Initializes a Keycard device with PIN, PUK, and pairing secret.

    Establishes an ephemeral ECDH key exchange and sends encrypted
    credentials to the card.

    Args:
        card: The card session object.
        pin (str | bytes): The personal identification number (PIN).
        puk (str | bytes): The personal unblocking key (PUK).
        pairing_secret (str | bytes): A 32-byte shared secret or a passphrase that
            will be converted into one.
        duress_pin (str | bytes | None): Optional duress PIN (6 digits).
            Requires applet version 3.1 or later, and can only be set during
            initialization. When omitted, the applet uses the first half of
            the PUK as the duress PIN. Defaults to None.
        pin_limit (int | None): Optional retry limit for PIN (2-10). Only
            sent if duress_pin is set or a limit is explicitly provided.
            Defaults to the applet default of 3.
        puk_limit (int | None): Optional retry limit for PUK (3-12). Only
            sent if duress_pin is set or a limit is explicitly provided.
            Defaults to the applet default of 5.

    Raises:
        NotSelectedError: If no card public key is provided.
        ValueError: If PIN/PUK/duress_pin format is invalid or data exceeds APDU length.
        APDUError: If the card returns a failure status word.
    '''
    if card.card_public_key is None:
        raise NotSelectedError('Card not selected. Call select() first.')

    if not isinstance(pin, bytes):
        pin = pin.encode('ascii')
    if not isinstance(puk, bytes):
        puk = puk.encode('ascii')
    if not isinstance(pairing_secret, bytes):
        pairing_secret = generate_pairing_token(pairing_secret)

    # Handle duress PIN and limits
    has_duress_pin = duress_pin is not None
    has_custom_limits = pin_limit is not None or puk_limit is not None

    if has_duress_pin:
        if not isinstance(duress_pin, bytes):
            duress_pin = duress_pin.encode('ascii')
        if len(duress_pin) != 6 or not duress_pin.isdigit():
            raise ValueError("Duress PIN must be exactly 6 digits.")

    # Set defaults for limits if duress PIN is set. Bounds and defaults match
    # the applet (PIN_MIN/MAX_RETRIES = 2/10, PUK_MIN/MAX_RETRIES = 3/12,
    # defaults 3 and 5); out-of-range values are rejected on-card with 0x6A80.
    if has_duress_pin or has_custom_limits:
        if pin_limit is None:
            pin_limit = 3
        if puk_limit is None:
            puk_limit = 5

        if not (2 <= pin_limit <= 10):
            raise ValueError("PIN retry limit must be between 2 and 10.")
        if not (3 <= puk_limit <= 12):
            raise ValueError("PUK retry limit must be between 3 and 12.")

    ephemeral_key = SigningKey.generate(curve=SECP256k1)
    our_pubkey_bytes: bytes = \
        ephemeral_key.verifying_key.to_string('uncompressed')
    card_pubkey = VerifyingKey.from_string(
        card.card_public_key,
        curve=SECP256k1
    )
    ecdh = ECDH(
        curve=SECP256k1,
        private_key=ephemeral_key,
        public_key=card_pubkey
    )
    shared_secret = ecdh.generate_sharedsecret_bytes()

    # Build plaintext based on what's provided
    plaintext: bytes = pin + puk + pairing_secret
    if has_duress_pin or has_custom_limits:
        plaintext += bytes([pin_limit, puk_limit])
    if has_duress_pin:
        plaintext += duress_pin

    iv: bytes = urandom(16)
    ciphertext: bytes = aes_cbc_encrypt(shared_secret, iv, plaintext)
    data: bytes = (
        bytes([len(our_pubkey_bytes)])
        + our_pubkey_bytes
        + iv
        + ciphertext
    )

    if len(data) > 255:
        raise ValueError('Data too long for single APDU')

    card.send_apdu(
        ins=constants.INS_INIT,
        data=data
    )
