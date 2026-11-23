"""
Módulo de primitivas criptográficas para VaultSign.
Separa la lógica criptográfica de la lógica de negocio y la persistencia.
"""

import base64
import hmac as std_hmac
import os
import re
from typing import Dict, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Parámetros criptográficos constantes (estándares actuales)
SCRYPT_N = 2**14        # 16384 iteraciones (~16 MB de RAM por derivación)
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32            # 256 bits
SALT_LEN = 16           # 128 bits
GCM_NONCE_LEN = 12      # 96 bits (recomendado por NIST SP 800-38D)
GCM_TAG_LEN = 16        # 128 bits


class CryptoError(Exception):
    """Error base para fallos criptográficos."""


class WeakPasswordError(CryptoError):
    """La contraseña no cumple la política de robustez."""


class IntegrityError(CryptoError):
    """Fallo de integridad o autenticidad (tag AEAD o HMAC inválido)."""


def generate_random_bytes(length: int) -> bytes:
    """Genera bytes aleatorios usando el CSPRNG del sistema operativo."""
    return os.urandom(length)


def validate_password_strength(password: str) -> None:
    """Exige al menos 10 caracteres, mayúscula, minúscula, dígito y símbolo."""
    if len(password) < 10:
        raise WeakPasswordError("La contraseña debe tener al menos 10 caracteres.")
    if not re.search(r"[A-Z]", password):
        raise WeakPasswordError("La contraseña debe incluir al menos una mayúscula.")
    if not re.search(r"[a-z]", password):
        raise WeakPasswordError("La contraseña debe incluir al menos una minúscula.")
    if not re.search(r"[0-9]", password):
        raise WeakPasswordError("La contraseña debe incluir al menos un número.")
    if not re.search(r"[^A-Za-z0-9]", password):
        raise WeakPasswordError("La contraseña debe incluir al menos un carácter especial.")


def derive_key_scrypt(password: str, salt: bytes, length: int = KEY_LEN) -> bytes:
    """Deriva una clave o hash seguro a partir de contraseña y salt usando scrypt."""
    kdf = Scrypt(salt=salt, length=length, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    """Verifica una contraseña en tiempo constante para evitar timing attacks."""
    candidate = derive_key_scrypt(password, salt, length=len(expected_hash))
    return std_hmac.compare_digest(candidate, expected_hash)


def derive_subkeys(master_key: bytes, salt: bytes) -> Dict[str, bytes]:
    """
    Deriva 3 claves independientes de 256 bits mediante HKDF-SHA256
    para garantizar separación de dominios criptográficos.
    """
    purposes = {
        "enc_key": b"vaultsign-v1-aes-256-gcm-docs",
        "mac_key": b"vaultsign-v1-hmac-sha256-audit",
        "keywrap_key": b"vaultsign-v1-aes-256-gcm-keywrap",
    }
    subkeys = {}
    for name, info in purposes.items():
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_LEN,
            salt=salt,
            info=info,
        )
        subkeys[name] = hkdf.derive(master_key)
    return subkeys


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> Dict[str, str]:
    """
    Cifrado autenticado AES-256-GCM.
    Genera un nonce aleatorio de 96 bits en cada llamada (jamás reutilizado).
    """
    if len(key) != KEY_LEN:
        raise CryptoError("La clave AES debe ser de 256 bits (32 bytes).")

    nonce = generate_random_bytes(GCM_NONCE_LEN)
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, aad)

    ciphertext = ct_and_tag[:-GCM_TAG_LEN]
    tag = ct_and_tag[-GCM_TAG_LEN:]

    return {
        "algorithm": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }


def aes_gcm_decrypt(
    key: bytes,
    nonce_b64: str,
    ciphertext_b64: str,
    tag_b64: str,
    aad: bytes,
) -> bytes:
    """
    Descifra y verifica integridad con AES-256-GCM.
    Rechaza los datos lanzando IntegrityError si falla el tag, el nonce o el AAD.
    """
    try:
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        tag = base64.b64decode(tag_b64)
        if len(nonce) != GCM_NONCE_LEN or len(tag) != GCM_TAG_LEN:
            raise IntegrityError("Longitud de nonce o tag GCM inválida.")
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, aad)
    except InvalidTag as exc:
        raise IntegrityError(
            "Verificación AES-256-GCM fallida: datos, tag, nonce o metadatos alterados."
        ) from exc
    except Exception as exc:
        if isinstance(exc, IntegrityError):
            raise
        raise IntegrityError(f"Error al procesar el bloque cifrado: {exc}") from exc


def compute_hmac_sha256(key: bytes, data: bytes) -> str:
    """Genera una etiqueta HMAC-SHA256 en formato hexadecimal."""
    if len(key) != KEY_LEN:
        raise CryptoError("La clave HMAC debe ser de 256 bits (32 bytes).")
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    return mac.finalize().hex()


def verify_hmac_sha256(key: bytes, data: bytes, expected_hex: str) -> None:
    """
    Verifica una etiqueta HMAC-SHA256 en tiempo constante.
    Lanza IntegrityError si no coincide.
    """
    try:
        expected_bytes = bytes.fromhex(expected_hex)
    except ValueError as exc:
        raise IntegrityError("Formato de etiqueta HMAC inválido.") from exc

    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    try:
        mac.verify(expected_bytes)
    except InvalidSignature as exc:
        raise IntegrityError(
            "Verificación HMAC-SHA256 fallida: el registro ha sido manipulado."
        ) from exc


def generate_ecdsa_keypair() -> Tuple[bytes, str]:
    """
    Genera un par de claves asimétricas ECDSA sobre la curva NIST P-256 (SECP256R1).
    Devuelve (clave_privada_pem_bytes, clave_publica_pem_str).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # Se cifra inmediatamente con AES-GCM
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    return private_pem, public_pem


def sign_ecdsa_sha256(private_pem: bytes, data: bytes) -> str:
    """Genera una firma digital ECDSA (P-256 + SHA-256) codificada en Base64."""
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode("ascii")


def verify_ecdsa_sha256(public_pem: str, data: bytes, signature_b64: str) -> bool:
    """Verifica una firma digital ECDSA (P-256 + SHA-256). Devuelve False si es inválida."""
    try:
        public_key = serialization.load_pem_public_key(public_pem.encode("ascii"))
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def sha256_hex(data: bytes) -> str:
    """Calcula el resumen criptográfico SHA-256 en hexadecimal."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()
