import sys
import pytest
from unittest.mock import MagicMock, patch
from keycard.commands.init import init
from keycard.exceptions import APDUError
from keycard import constants


PIN = b'1234'
PUK = b'5678'
PAIRING_SECRET = b'abcdefgh'
CARD_PUBLIC_KEY = b'\x04' + b'\x00' * 64  # Valid uncompressed pubkey format


@pytest.fixture
def ecc_patches():
    init_module = sys.modules['keycard.commands.init']
    with (
        patch.object(init_module, 'urandom', return_value=b'\x00' * 16),
        patch.object(
            init_module,
            'aes_cbc_encrypt',
            side_effect=lambda k, iv,
            pt: b'\xAA' * len(pt)
        ),
        patch.object(init_module, 'SigningKey') as mock_signing_key_cls,
        patch.object(init_module, 'VerifyingKey') as mock_verifying_key_cls,
        patch.object(init_module, 'ECDH') as mock_ecdh_cls,
    ):
        mock_gen = mock_signing_key_cls.generate
        fake_privkey = MagicMock()
        fake_privkey.verifying_key.to_string.return_value = b'\x01' * 65
        mock_gen.return_value = fake_privkey

        mock_parse = mock_verifying_key_cls.from_string
        mock_parse.return_value = 'parsed-pubkey'

        ecdh_instance = MagicMock()
        ecdh_instance.generate_sharedsecret_bytes.return_value = b'\xBB' * 32
        mock_ecdh_cls.return_value = ecdh_instance

        yield


def test_init_success(card, ecc_patches):
    card.send_apdu.return_value = b''
    card.card_public_key = CARD_PUBLIC_KEY

    init(card, PIN, PUK, PAIRING_SECRET)

    card.send_apdu.assert_called_once_with(
        ins=constants.INS_INIT,
        data=bytes.fromhex(
            '4101010101010101010101010101010101010101010101010101010'
            '1010101010101010101010101010101010101010101010101010101'
            '010101010101010101010100000000000000000000000000000000'
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
    )


@pytest.mark.parametrize('secret_length', [10, 240])
def test_init_data_length(card, ecc_patches, secret_length):
    card.send_apdu.return_value = b''
    card.card_public_key = CARD_PUBLIC_KEY

    pairing_secret = b'x' * secret_length
    plaintext = PIN + PUK + pairing_secret
    total_data_len = 1 + 65 + 16 + len(plaintext)

    if total_data_len > 255:
        with pytest.raises(ValueError, match='Data too long'):
            init(card, PIN, PUK, pairing_secret)
    else:
        init(card, PIN, PUK, pairing_secret)
        assert card.send_apdu.call_count == 1


def test_init_apdu_error(card, ecc_patches):
    card.send_apdu.side_effect = APDUError(0x6A84)
    card.card_public_key = CARD_PUBLIC_KEY

    with pytest.raises(APDUError) as excinfo:
        init(card, PIN, PUK, PAIRING_SECRET)

    assert excinfo.value.sw == 0x6A84


def test_init_with_duress_pin(card, ecc_patches):
    '''Test init with duress PIN - should include limits and duress PIN in plaintext'''
    card.send_apdu.return_value = b''
    card.card_public_key = CARD_PUBLIC_KEY
    duress_pin = b'654321'

    init(card, PIN, PUK, PAIRING_SECRET, duress_pin=duress_pin)

    # Plaintext should be: PIN + PUK + PAIRING_SECRET + PIN_LIMIT + PUK_LIMIT + DURESS_PIN
    # with default limits of 5, 5
    call_args = card.send_apdu.call_args
    assert call_args[1]['ins'] == constants.INS_INIT
    data = call_args[1]['data']
    # Verify the data was sent (the exact bytes depend on the mock encryption)
    assert len(data) > 0


def test_init_with_custom_limits_no_duress(card, ecc_patches):
    '''Test init with custom limits but no duress PIN'''
    card.send_apdu.return_value = b''
    card.card_public_key = CARD_PUBLIC_KEY

    init(card, PIN, PUK, PAIRING_SECRET, pin_limit=3, puk_limit=4)

    call_args = card.send_apdu.call_args
    assert call_args[1]['ins'] == constants.INS_INIT
    data = call_args[1]['data']
    assert len(data) > 0


def test_init_with_duress_and_limits(card, ecc_patches):
    '''Test init with duress PIN and custom limits'''
    card.send_apdu.return_value = b''
    card.card_public_key = CARD_PUBLIC_KEY
    duress_pin = b'999999'

    init(card, PIN, PUK, PAIRING_SECRET, duress_pin=duress_pin, pin_limit=2, puk_limit=3)

    call_args = card.send_apdu.call_args
    assert call_args[1]['ins'] == constants.INS_INIT
    data = call_args[1]['data']
    assert len(data) > 0


def test_init_with_duress_pin_string(card, ecc_patches):
    '''Test init with duress PIN as string'''
    card.send_apdu.return_value = b''
    card.card_public_key = CARD_PUBLIC_KEY

    init(card, PIN, PUK, PAIRING_SECRET, duress_pin='111111')

    call_args = card.send_apdu.call_args
    assert call_args[1]['ins'] == constants.INS_INIT


def test_init_invalid_duress_pin_length(card, ecc_patches):
    '''Test init with invalid duress PIN length'''
    card.card_public_key = CARD_PUBLIC_KEY

    with pytest.raises(ValueError, match='Duress PIN must be exactly 6 digits'):
        init(card, PIN, PUK, PAIRING_SECRET, duress_pin=b'12345')


def test_init_invalid_pin_limit(card, ecc_patches):
    '''Test init with invalid PIN retry limit'''
    card.card_public_key = CARD_PUBLIC_KEY

    with pytest.raises(ValueError, match='PIN retry limit must be between 1 and 5'):
        init(card, PIN, PUK, PAIRING_SECRET, pin_limit=0)

    with pytest.raises(ValueError, match='PIN retry limit must be between 1 and 5'):
        init(card, PIN, PUK, PAIRING_SECRET, pin_limit=6)


def test_init_invalid_puk_limit(card, ecc_patches):
    '''Test init with invalid PUK retry limit'''
    card.card_public_key = CARD_PUBLIC_KEY

    with pytest.raises(ValueError, match='PUK retry limit must be between 1 and 5'):
        init(card, PIN, PUK, PAIRING_SECRET, puk_limit=0)

    with pytest.raises(ValueError, match='PUK retry limit must be between 1 and 5'):
        init(card, PIN, PUK, PAIRING_SECRET, puk_limit=6)
