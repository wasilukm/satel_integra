# -*- coding: utf-8 -*-
import os
from typing import List
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_LENGTH = 16


class EncryptionHandler:

    """Encryption handler for Satel integration protocol.

    :param integration_key: Satel integration key

    """

    def __init__(self, integration_key: str):
        encryption_key = self._integration_key_to_encryption_key(integration_key)
        self.cipher = Cipher(algorithms.AES(encryption_key), modes.ECB())
        self._rolling_counter: int = 0
        self._id_s: int = 0
        self._id_r: int = 0

    @classmethod
    def _integration_key_to_encryption_key(cls, integration_key: str) -> bytes:
        """Convert Satel integration key into encryption key."""
        integration_key_bytes = bytes(integration_key, 'ascii')
        key = [0] * 24
        for i in range(12):
            key[i] = key[i + 12] = integration_key_bytes[i] if len(integration_key_bytes) > i else 0x20
        return bytes(key)

    @classmethod
    def _bytes_to_blocks(cls, message: bytes, block_len: int) -> List[bytes]:
        """Split message into list of blocks of equal length."""
        return [message[i:i + block_len] for i in range(0, len(message), block_len)]

    def _prepare_header(self) -> bytes:
        header = (os.urandom(2) +
                  self._rolling_counter.to_bytes(2, 'big') +
                  os.urandom(1) +
                  self._id_r.to_bytes(1, 'big'))
        self._rolling_counter += 1
        self._rolling_counter &= 0xFFFF
        self._id_s = header[4]
        return header

    def encrypt(self, pdu: bytes) -> bytes:
        """Encrypt protocol data unit."""
        if len(pdu) < BLOCK_LENGTH:
            pdu += b'\x00' * (BLOCK_LENGTH - len(pdu))
        encrypted_pdu = []
        encryptor = self.cipher.encryptor()
        cv = [0] * BLOCK_LENGTH
        cv = list(encryptor.update(bytes(cv)))
        for block in self._bytes_to_blocks(pdu, BLOCK_LENGTH):
            p = list(block)
            if len(block) == BLOCK_LENGTH:
                p = [a ^ b for a, b in zip(p, cv)]
                p = list(encryptor.update(bytes(p)))
                cv = list(p)
            else:
                cv = list(encryptor.update(bytes(cv)))
                p = [a ^ b for a, b in zip(p, cv)]
            encrypted_pdu += p
        return bytes(encrypted_pdu)

    def prepare_pdu(self, message: bytes) -> bytes:
        """Prepare protocol data unit."""
        pdu = self._prepare_header() + message
        encrypted_pdu = self.encrypt(pdu)
        return encrypted_pdu

    def decrypt(self, pdu: bytes) -> bytes:
        """Decrypt message."""
        decrypted_pdu = []
        cv = [0] * BLOCK_LENGTH
        decryptor = self.cipher.decryptor()
        encryptor = self.cipher.encryptor()
        cv = list(encryptor.update(bytes(cv)))
        for block in self._bytes_to_blocks(pdu, BLOCK_LENGTH):
            temp = list(block)
            c = list(block)
            if len(block) == BLOCK_LENGTH:
                c = list(decryptor.update(bytes(c)))
                c = [a ^ b for a, b in zip(c, cv)]
                cv = list(temp)
            else:
                cv = list(encryptor.update(bytes(cv)))
                c = [a ^ b for a, b in zip(c, cv)]
            decrypted_pdu += c
        return bytes(decrypted_pdu)

    def extract_data_from_pdu(self, pdu: bytes) -> bytes:
        """Extract data from protocol data unit."""
        decrypted_pdu = self.decrypt(pdu)
        header = decrypted_pdu[:6]
        data = decrypted_pdu[6:]
        self._id_r = header[4]
        if self._id_s != decrypted_pdu[5]:
            raise RuntimeError(
                f'Incorrect value of ID_S, received \\x{decrypted_pdu[5]:x} but expected \\x{self._id_s:x}\n'
                'Decrypted data: %s' % ''.join('\\x{:02x}'.format(x) for x in decrypted_pdu))
        return bytes(data)
