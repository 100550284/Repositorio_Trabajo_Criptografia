"""
Suite de pruebas positivas y negativas de seguridad para VaultSign.
Ejecución: python -m unittest -v test_security.py
"""

import base64
import json
import tempfile
import unittest
from pathlib import Path

from app import AuthError, VaultSignApp
from crypto_utils import IntegrityError, WeakPasswordError


class TestVaultSignSecurity(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.app = VaultSignApp(data_dir=self.tmp_dir.name, verbose=False)
        self.user = "alvaro"
        self.pwd = "Str0ng!Pass2026"
        self.app.register_user(self.user, self.pwd)
        self.session = self.app.login(self.user, self.pwd)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _tamper_json(self, filename: str, mutator) -> None:
        path = Path(self.tmp_dir.name) / filename
        data = json.loads(path.read_text(encoding="utf-8"))
        mutator(data)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # --- 1. AUTENTICACIÓN ---
    def test_01_weak_password_rejected(self) -> None:
        with self.assertRaises(WeakPasswordError):
            self.app.register_user("usuario_debil", "123456")

    def test_02_wrong_password_rejected(self) -> None:
        with self.assertRaises(AuthError):
            self.app.login(self.user, "Wrong!Pass2026")

    # --- 2. CIFRADO AES-256-GCM (POSITIVAS Y NEGATIVAS) ---
    def test_03_encrypt_decrypt_and_unique_nonces(self) -> None:
        doc1 = self.app.save_document(self.session, "Nota 1", "Mismo secreto")
        doc2 = self.app.save_document(self.session, "Nota 2", "Mismo secreto")

        self.assertEqual(self.app.read_document(self.session, doc1)["content"], "Mismo secreto")

        vault = self.app.storage.load_json(f"vault_{self.user}.json", {})
        self.assertNotEqual(vault[doc1]["nonce"], vault[doc2]["nonce"])
        self.assertNotEqual(vault[doc1]["ciphertext"], vault[doc2]["ciphertext"])

    def test_04_tampered_ciphertext_rejected(self) -> None:
        doc_id = self.app.save_document(self.session, "Contrato", "Importe: 1000 EUR")

        def flip_bit(vault):
            raw = bytearray(base64.b64decode(vault[doc_id]["ciphertext"]))
            raw[0] ^= 0x01  # Modifica 1 solo bit
            vault[doc_id]["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")

        self._tamper_json(f"vault_{self.user}.json", flip_bit)

        with self.assertRaises(IntegrityError):
            self.app.read_document(self.session, doc_id)

    def test_05_tampered_gcm_tag_rejected(self) -> None:
        doc_id = self.app.save_document(self.session, "Clave", "Datos sensibles")

        def flip_tag(vault):
            raw = bytearray(base64.b64decode(vault[doc_id]["tag"]))
            raw[-1] ^= 0xFF
            vault[doc_id]["tag"] = base64.b64encode(bytes(raw)).decode("ascii")

        self._tamper_json(f"vault_{self.user}.json", flip_tag)

        with self.assertRaises(IntegrityError):
            self.app.read_document(self.session, doc_id)

    def test_06_tampered_aad_metadata_rejected(self) -> None:
        """Simula ataque de sustitución cambiando el título sin tocar el ciphertext."""
        doc_id = self.app.save_document(self.session, "Título Original", "Contenido privado")

        def change_title(vault):
            vault[doc_id]["title"] = "Título Falso"

        self._tamper_json(f"vault_{self.user}.json", change_title)

        with self.assertRaises(IntegrityError):
            self.app.read_document(self.session, doc_id)

    # --- 3. INTEGRIDAD HMAC-SHA256 Y ANTI-REPLAY ---
    def test_07_tampered_audit_log_hmac_rejected(self) -> None:
        self.app.save_document(self.session, "Informe", "Texto")
        self.assertGreaterEqual(self.app.verify_audit_log(self.session), 3)

        def tamper_event(log):
            log[-1]["detail"] = "evento falsificado"

        self._tamper_json(f"audit_{self.user}.json", tamper_event)

        with self.assertRaises(IntegrityError):
            self.app.verify_audit_log(self.session)

    def test_08_replay_or_deleted_audit_entry_rejected(self) -> None:
        """Simula borrado o repetición (replay) de entradas del historial."""
        self.app.save_document(self.session, "Doc A", "Contenido A")

        def duplicate_entry(log):
            log.append(dict(log[-1]))  # Replay de la última entrada

        self._tamper_json(f"audit_{self.user}.json", duplicate_entry)

        with self.assertRaises(IntegrityError):
            self.app.verify_audit_log(self.session)

    # --- 4. FIRMA DIGITAL ECDSA ---
    def test_09_valid_and_tampered_digital_signature(self) -> None:
        doc_id = self.app.save_document(self.session, "Acta", "Aprobado por unanimidad")
        signed_id = self.app.sign_document(self.session, doc_id)

        # Verificación positiva
        ok, _ = self.app.verify_signed_document(signed_id)
        self.assertTrue(ok)

        # Verificación negativa 1: alterar 1 byte de la firma
        def corrupt_sig(store):
            raw = bytearray(base64.b64decode(store[signed_id]["signature"]))
            raw[5] ^= 0x01
            store[signed_id]["signature"] = base64.b64encode(bytes(raw)).decode("ascii")

        self._tamper_json("signed_docs.json", corrupt_sig)
        ok, _ = self.app.verify_signed_document(signed_id)
        self.assertFalse(ok)

    def test_10_signature_impersonation_rejected(self) -> None:
        """Comprueba que la firma de un usuario no valida con la clave pública de otro."""
        self.app.register_user("otro_user", "An0ther!Pass2026")
        doc_id = self.app.save_document(self.session, "Recibo", "Pago realizado")
        signed_id = self.app.sign_document(self.session, doc_id)

        ok, _ = self.app.verify_signed_document(signed_id, expected_signer="otro_user")
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
    