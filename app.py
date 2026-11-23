"""
Lógica principal de VaultSign: gestión de usuarios, documentos cifrados,
firmas digitales y registro de auditoría con HMAC.
"""

import base64
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import crypto_utils as cu
from storage import SecureStorage


class AuthError(Exception):
    """Error de autenticación o registro."""


class NotFoundError(Exception):
    """Recurso no encontrado."""


@dataclass
class UserSession:
    """Claves derivadas mantenidas únicamente en memoria RAM durante la sesión."""
    username: str
    enc_key: bytes
    mac_key: bytes
    private_key_pem: bytes


class VaultSignApp:
    """Aplicación principal de gestión segura de documentos."""

    def __init__(self, data_dir: str = "data", verbose: bool = True) -> None:
        self.storage = SecureStorage(data_dir)
        self.verbose = verbose

    def _debug(self, message: str) -> None:
        """Muestra trazas de depuración criptográfica sin revelar jamás secretos."""
        if self.verbose:
            print(f"[CRYPTO-LOG] {message}")

    @staticmethod
    def _validate_username(username: str) -> None:
        if not re.fullmatch(r"[a-zA-Z0-9_]{3,24}", username):
            raise AuthError("El usuario debe tener entre 3 y 24 caracteres alfanuméricos o '_'.")

    @staticmethod
    def _canonical_json(payload: dict) -> bytes:
        """Serialización determinista para HMAC y firma digital."""
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # ------------------------------------------------------------------
    # 1. REGISTRO Y AUTENTICACIÓN DE USUARIOS
    # ------------------------------------------------------------------
    def register_user(self, username: str, password: str) -> None:
        self._validate_username(username)
        cu.validate_password_strength(password)

        users = self.storage.load_json(self.storage.users_file(), {})
        if username in users:
            raise AuthError(f"El usuario '{username}' ya existe.")

        # Sales independientes para autenticación y derivación de claves
        salt_auth = cu.generate_random_bytes(cu.SALT_LEN)
        salt_kdf = cu.generate_random_bytes(cu.SALT_LEN)
        auth_hash = cu.derive_key_scrypt(password, salt_auth)

        # Derivación temporal en RAM para proteger la clave privada y crear el log inicial
        master_key = cu.derive_key_scrypt(password, salt_kdf)
        subkeys = cu.derive_subkeys(master_key, salt_kdf)

        # Generación del par ECDSA P-256 y protección de la clave privada con AES-256-GCM
        priv_pem, pub_pem = cu.generate_ecdsa_keypair()
        priv_aad = f"ecdsa-privkey|{username}".encode("utf-8")
        encrypted_priv = cu.aes_gcm_encrypt(subkeys["keywrap_key"], priv_pem, priv_aad)

        users[username] = {
            "kdf": f"scrypt(N={cu.SCRYPT_N},r={cu.SCRYPT_R},p={cu.SCRYPT_P})",
            "salt_auth": base64.b64encode(salt_auth).decode("ascii"),
            "auth_hash": base64.b64encode(auth_hash).decode("ascii"),
            "salt_kdf": base64.b64encode(salt_kdf).decode("ascii"),
            "ecdsa_curve": "SECP256R1",
            "public_key_pem": pub_pem,
            "encrypted_private_key": encrypted_priv,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.storage.save_json(self.storage.users_file(), users)
        self.storage.save_json(self.storage.vault_file(username), {})
        self.storage.save_json(self.storage.audit_file(username), [])

        temp_session = UserSession(
            username=username,
            enc_key=subkeys["enc_key"],
            mac_key=subkeys["mac_key"],
            private_key_pem=priv_pem,
        )
        self._append_audit_event(temp_session, "USER_REGISTERED", "Alta de cuenta y par ECDSA P-256")

        self._debug(
            f"Usuario '{username}' registrado | Auth: scrypt (salt 128b) | "
            f"Firma: ECDSA P-256 | Clave privada cifrada con AES-256-GCM "
            f"(nonce={encrypted_priv['nonce'][:12]}...)"
        )

    def login(self, username: str, password: str) -> UserSession:
        users = self.storage.load_json(self.storage.users_file(), {})
        record = users.get(username)
        if not record:
            raise AuthError("Credenciales inválidas.")

        salt_auth = base64.b64decode(record["salt_auth"])
        expected_hash = base64.b64decode(record["auth_hash"])

        if not cu.verify_password(password, salt_auth, expected_hash):
            self._debug(f"Autenticación FALLIDA para '{username}' (hash scrypt no coincide).")
            raise AuthError("Credenciales inválidas.")

        # Reconstrucción de claves simétricas en memoria RAM
        salt_kdf = base64.b64decode(record["salt_kdf"])
        master_key = cu.derive_key_scrypt(password, salt_kdf)
        subkeys = cu.derive_subkeys(master_key, salt_kdf)

        # Descifrado y verificación de la clave privada ECDSA
        enc_priv = record["encrypted_private_key"]
        priv_aad = f"ecdsa-privkey|{username}".encode("utf-8")
        priv_pem = cu.aes_gcm_decrypt(
            subkeys["keywrap_key"],
            enc_priv["nonce"],
            enc_priv["ciphertext"],
            enc_priv["tag"],
            priv_aad,
        )

        session = UserSession(
            username=username,
            enc_key=subkeys["enc_key"],
            mac_key=subkeys["mac_key"],
            private_key_pem=priv_pem,
        )

        # Comprobación automática de la integridad del log de auditoría al entrar
        self.verify_audit_log(session)
        self._append_audit_event(session, "USER_LOGIN", "Inicio de sesión verificado")

        self._debug(
            f"Login OK para '{username}' | Subclaves derivadas con HKDF-SHA256 (256 bits c/u) | "
            f"Clave privada ECDSA descifrada y audit log íntegro."
        )
        return session

    # ------------------------------------------------------------------
    # 2. CIFRADO / DESCIFRADO DE DOCUMENTOS (AES-256-GCM)
    # ------------------------------------------------------------------
    def save_document(self, session: UserSession, title: str, content: str) -> str:
        if not title.strip() or not content.strip():
            raise ValueError("El título y el contenido no pueden estar vacíos.")

        doc_id = secrets.token_hex(6)
        version = 1
        aad = f"{session.username}|{doc_id}|{version}|{title}".encode("utf-8")
        encrypted = cu.aes_gcm_encrypt(session.enc_key, content.encode("utf-8"), aad)

        vault = self.storage.load_json(self.storage.vault_file(session.username), {})
        vault[doc_id] = {
            "doc_id": doc_id,
            "owner": session.username,
            "version": version,
            "title": title,
            "created_at": datetime.now(timezone.utc).isoformat(),
            **encrypted,
        }
        self.storage.save_json(self.storage.vault_file(session.username), vault)
        self._append_audit_event(session, "DOC_ENCRYPTED", f"doc_id={doc_id}, title={title}")

        self._debug(
            f"Documento '{doc_id}' cifrado | Algoritmo: AES-256-GCM (clave 256b) | "
            f"Nonce(96b)={encrypted['nonce']} | Tag(128b)={encrypted['tag']}"
        )
        return doc_id

    def read_document(self, session: UserSession, doc_id: str) -> Dict[str, str]:
        vault = self.storage.load_json(self.storage.vault_file(session.username), {})
        entry = vault.get(doc_id)
        if not entry:
            raise NotFoundError(f"No existe el documento '{doc_id}'.")

        aad = f"{session.username}|{entry['doc_id']}|{entry['version']}|{entry['title']}".encode("utf-8")
        plaintext_bytes = cu.aes_gcm_decrypt(
            session.enc_key,
            entry["nonce"],
            entry["ciphertext"],
            entry["tag"],
            aad,
        )

        self._debug(
            f"Documento '{doc_id}' descifrado y autenticado OK | "
            f"Algoritmo: AES-256-GCM | AAD verificado."
        )
        return {
            "doc_id": doc_id,
            "title": entry["title"],
            "content": plaintext_bytes.decode("utf-8"),
            "created_at": entry["created_at"],
        }

    def list_documents(self, session: UserSession) -> List[Dict[str, str]]:
        vault = self.storage.load_json(self.storage.vault_file(session.username), {})
        return [
            {"doc_id": d["doc_id"], "title": d["title"], "created_at": d["created_at"]}
            for d in vault.values()
        ]

    # ------------------------------------------------------------------
    # 3. INTEGRIDAD DEL REGISTRO DE AUDITORÍA (HMAC-SHA256 ENCADENADO)
    # ------------------------------------------------------------------
    def _append_audit_event(self, session: UserSession, action: str, detail: str) -> None:
        log = self.storage.load_json(self.storage.audit_file(session.username), [])
        seq = len(log) + 1
        prev_hmac = log[-1]["hmac"] if log else ("0" * 64)

        body = {
            "seq": seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "username": session.username,
            "action": action,
            "detail": detail,
            "prev_hmac": prev_hmac,
        }
        tag_hex = cu.compute_hmac_sha256(session.mac_key, self._canonical_json(body))
        log.append({**body, "hmac": tag_hex})
        self.storage.save_json(self.storage.audit_file(session.username), log)

        self._debug(
            f"Audit #{seq} ({action}) protegido | Algoritmo: HMAC-SHA256 (clave 256b) | "
            f"MAC={tag_hex[:16]}..."
        )

    def verify_audit_log(self, session: UserSession) -> int:
        """
        Verifica toda la cadena de auditoría: detecta modificación de campos,
        borrado, inserción o repetición/reordenamiento (replay).
        """
        log = self.storage.load_json(self.storage.audit_file(session.username), [])
        expected_prev = "0" * 64

        for idx, entry in enumerate(log, start=1):
            if entry.get("seq") != idx:
                raise cu.IntegrityError(
                    f"Secuencia de auditoría alterada en entrada {idx} (posible borrado/replay)."
                )
            if entry.get("prev_hmac") != expected_prev:
                raise cu.IntegrityError(
                    f"Cadena HMAC rota en entrada {idx} (posible reordenamiento o borrado)."
                )

            body = {
                "seq": entry["seq"],
                "timestamp": entry["timestamp"],
                "username": entry["username"],
                "action": entry["action"],
                "detail": entry["detail"],
                "prev_hmac": entry["prev_hmac"],
            }
            cu.verify_hmac_sha256(session.mac_key, self._canonical_json(body), entry["hmac"])
            expected_prev = entry["hmac"]

        self._debug(
            f"Audit log verificado OK ({len(log)} entradas) | Algoritmo: HMAC-SHA256 (clave 256b)."
        )
        return len(log)

    # ------------------------------------------------------------------
    # 4. FIRMA DIGITAL (ECDSA SECP256R1 + SHA-256)
    # ------------------------------------------------------------------
    def sign_document(self, session: UserSession, doc_id: str) -> str:
        """Firma digitalmente un documento descifrado y publica un paquete verificable."""
        doc = self.read_document(session, doc_id)
        signed_id = secrets.token_hex(6)

        payload = {
            "signed_id": signed_id,
            "signer": session.username,
            "doc_id": doc["doc_id"],
            "title": doc["title"],
            "content": doc["content"],
            "content_sha256": cu.sha256_hex(doc["content"].encode("utf-8")),
            "signed_at": datetime.now(timezone.utc).isoformat(),
            "sign_nonce": secrets.token_hex(16),  # Evita firmas repetidas idénticas
        }
        signature_b64 = cu.sign_ecdsa_sha256(
            session.private_key_pem, self._canonical_json(payload)
        )

        signed_store = self.storage.load_json(self.storage.signed_file(), {})
        signed_store[signed_id] = {
            "algorithm": "ECDSA-SECP256R1-SHA256",
            "payload": payload,
            "signature": signature_b64,
        }
        self.storage.save_json(self.storage.signed_file(), signed_store)
        self._append_audit_event(session, "DOC_SIGNED", f"signed_id={signed_id}, doc_id={doc_id}")

        self._debug(
            f"Documento firmado | signed_id={signed_id} | Algoritmo: ECDSA P-256 (256b) + SHA-256 | "
            f"Firma={signature_b64[:20]}..."
        )
        return signed_id

    def verify_signed_document(
        self, signed_id: str, expected_signer: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Verifica una firma digital usando la clave pública del firmante.
        No requiere iniciar sesión: cualquier tercero puede comprobar autoría e integridad.
        """
        signed_store = self.storage.load_json(self.storage.signed_file(), {})
        record = signed_store.get(signed_id)
        if not record:
            return False, f"No existe el paquete firmado '{signed_id}'."

        payload = record["payload"]
        signer = expected_signer or payload.get("signer")

        users = self.storage.load_json(self.storage.users_file(), {})
        user_record = users.get(signer)
        if not user_record:
            return False, f"No se encontró la clave pública del firmante '{signer}'."

        # 1. Comprobación de coherencia del hash del contenido
        recomputed_hash = cu.sha256_hex(payload["content"].encode("utf-8"))
        if recomputed_hash != payload.get("content_sha256"):
            self._debug(f"Firma '{signed_id}' RECHAZADA: contenido alterado respecto a SHA-256.")
            return False, "RECHAZADO: el contenido del documento ha sido modificado."

        # 2. Verificación criptográfica ECDSA con la clave pública
        is_valid = cu.verify_ecdsa_sha256(
            user_record["public_key_pem"],
            self._canonical_json(payload),
            record["signature"],
        )
        if not is_valid:
            self._debug(
                f"Firma '{signed_id}' RECHAZADA | Algoritmo: ECDSA-SECP256R1-SHA256 | "
                f"Firmante probado: '{signer}'."
            )
            return False, "RECHAZADO: firma digital inválida o manipulada."

        self._debug(
            f"Firma '{signed_id}' VÁLIDA | Algoritmo: ECDSA-SECP256R1-SHA256 (256b) | "
            f"Autoría confirmada: '{signer}'."
        )
        return True, f"VÁLIDA: firmado por '{signer}' el {payload['signed_at']}."
    