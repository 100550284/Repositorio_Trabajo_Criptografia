"""
Suite de pruebas positivas y negativas de seguridad para CadenaFría.
Ejecución: python -m unittest -v test_security.py
"""

import base64
import json
import tempfile
import unittest
from pathlib import Path

from app import AuthError, CadenaFriaApp
from crypto_utils import IntegrityError, WeakPasswordError


class TestCadenaFriaSecurity(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.app = CadenaFriaApp(data_dir=self.tmp_dir.name, verbose=False)
        self.operador = "transportes_sur"
        self.pwd = "FrioSeguro!2026"
        self.app.registrar_operador(self.operador, self.pwd)
        self.sesion = self.app.iniciar_sesion(self.operador, self.pwd)

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
            self.app.registrar_operador("operador_debil", "123456")

    def test_02_wrong_password_rejected(self) -> None:
        with self.assertRaises(AuthError):
            self.app.iniciar_sesion(self.operador, "ClaveMala!2026")

    # --- 2. CIFRADO AES-256-GCM Y AAD TÉRMICO ---
    def test_03_encrypt_decrypt_lote_and_unique_nonces(self) -> None:
        lote1 = self.app.crear_lote(
            self.sesion, "Vacuna A", 2.0, 8.0, "Hospital La Paz", "Valor 45000 EUR"
        )
        lote2 = self.app.crear_lote(
            self.sesion, "Vacuna A", 2.0, 8.0, "Hospital La Paz", "Valor 45000 EUR"
        )

        leido = self.app.leer_lote(self.sesion, lote1)
        self.assertEqual(leido["cliente_destino"], "Hospital La Paz")
        self.assertEqual(leido["datos_comerciales"], "Valor 45000 EUR")

        lotes = self.app.storage.load_json(f"lotes_{self.operador}.json", {})
        self.assertNotEqual(lotes[lote1]["nonce"], lotes[lote2]["nonce"])
        self.assertNotEqual(lotes[lote1]["ciphertext"], lotes[lote2]["ciphertext"])

    def test_04_tampered_ciphertext_rejected(self) -> None:
        lote_id = self.app.crear_lote(
            self.sesion, "Insulina", 2.0, 8.0, "Clínica Centro", "Fórmula secreta"
        )

        def flip_bit(lotes):
            raw = bytearray(base64.b64decode(lotes[lote_id]["ciphertext"]))
            raw[0] ^= 0x01
            lotes[lote_id]["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")

        self._tamper_json(f"lotes_{self.operador}.json", flip_bit)

        with self.assertRaises(IntegrityError):
            self.app.leer_lote(self.sesion, lote_id)

    def test_05_tampered_gcm_tag_rejected(self) -> None:
        lote_id = self.app.crear_lote(
            self.sesion, "Plasma", -25.0, -18.0, "Banco Sangre", "Lote crítico"
        )

        def flip_tag(lotes):
            raw = bytearray(base64.b64decode(lotes[lote_id]["tag"]))
            raw[-1] ^= 0xFF
            lotes[lote_id]["tag"] = base64.b64encode(bytes(raw)).decode("ascii")

        self._tamper_json(f"lotes_{self.operador}.json", flip_tag)

        with self.assertRaises(IntegrityError):
            self.app.leer_lote(self.sesion, lote_id)

    def test_06_tampered_temperature_limits_aad_rejected(self) -> None:
        """Simula un fraude ampliando temp_max en disco para ocultar un fallo de frío."""
        lote_id = self.app.crear_lote(
            self.sesion, "Vacuna ARNm", 2.0, 8.0, "Hospital 12 de Octubre", "Coste 80000 EUR"
        )

        def widen_limit(lotes):
            lotes[lote_id]["temp_max"] = 25.0

        self._tamper_json(f"lotes_{self.operador}.json", widen_limit)

        with self.assertRaises(IntegrityError):
            self.app.leer_lote(self.sesion, lote_id)

    # --- 3. TELEMETRÍA ENCADENADA HMAC-SHA256 ---
    def test_07_tampered_temperature_reading_rejected(self) -> None:
        """Simula maquillar una temperatura fuera de rango (14.5 °C -> 5.0 °C)."""
        lote_id = self.app.crear_lote(
            self.sesion, "Vacuna Gripe", 2.0, 8.0, "Farmacia Norte", "Pedido #402"
        )
        self.app.registrar_lectura(self.sesion, lote_id, "Salida Almacén", 4.2)
        self.app.registrar_lectura(self.sesion, lote_id, "Parada Burgos", 14.5)

        def fake_temp(telemetria):
            telemetria[lote_id][1]["temperatura_c"] = 5.0
            telemetria[lote_id][1]["en_rango"] = True

        self._tamper_json(f"telemetria_{self.operador}.json", fake_temp)

        with self.assertRaises(IntegrityError):
            self.app.verificar_telemetria(self.sesion, lote_id)

    def test_08_deleted_or_replayed_reading_rejected(self) -> None:
        """Simula borrar una lectura con alerta o repetir (replay) una lectura válida."""
        lote_id = self.app.crear_lote(
            self.sesion, "Pescado Fresco", 0.0, 4.0, "Mercamadrid", "Carga 2T"
        )
        self.app.registrar_lectura(self.sesion, lote_id, "Puerto Vigo", 1.8)
        self.app.registrar_lectura(self.sesion, lote_id, "Benavente", 9.5)
        self.app.registrar_lectura(self.sesion, lote_id, "Llegada Madrid", 2.1)

        # Intento de borrar la lectura #2 (la del fallo de frío)
        def delete_middle(telemetria):
            del telemetria[lote_id][1]

        self._tamper_json(f"telemetria_{self.operador}.json", delete_middle)

        with self.assertRaises(IntegrityError):
            self.app.verificar_telemetria(self.sesion, lote_id)

    def test_09_replay_reading_rejected(self) -> None:
        """Simula duplicar (replay) una lectura válida al final de la cadena."""
        lote_id = self.app.crear_lote(
            self.sesion, "Suero", 2.0, 8.0, "Hospital Clínico", "Ref 991"
        )
        self.app.registrar_lectura(self.sesion, lote_id, "Origen", 4.0)

        def replay_entry(telemetria):
            telemetria[lote_id].append(dict(telemetria[lote_id][-1]))

        self._tamper_json(f"telemetria_{self.operador}.json", replay_entry)

        with self.assertRaises(IntegrityError):
            self.app.verificar_telemetria(self.sesion, lote_id)

    # --- 4. FIRMA DIGITAL ECDSA DE ALBARANES ---
    def test_10_valid_and_tampered_albaran_signature(self) -> None:
        lote_id = self.app.crear_lote(
            self.sesion, "Vacuna Covid", 2.0, 8.0, "Hospital Gregorio Marañón", "1000 dosis"
        )
        self.app.registrar_lectura(self.sesion, lote_id, "Almacén", 3.5)
        self.app.registrar_lectura(self.sesion, lote_id, "Entrega", 11.2)  # Rompe cadena

        alb_id, estado = self.app.emitir_albaran(self.sesion, lote_id)
        self.assertEqual(estado, "CADENA_FRIA_ROTA")

        # Verificación positiva pública (sin sesión)
        ok, msg = self.app.verificar_albaran(alb_id)
        self.assertTrue(ok)
        self.assertIn("CADENA_FRIA_ROTA", msg)

        # Ataque: falsificar el estado a INTACTA en el albarán firmado
        def forge_status(albaranes):
            albaranes[alb_id]["payload"]["resumen_telemetria"]["estado_cadena"] = (
                "CADENA_FRIA_INTACTA"
            )

        self._tamper_json("albaranes_firmados.json", forge_status)
        ok, _ = self.app.verificar_albaran(alb_id)
        self.assertFalse(ok)

    def test_11_albaran_impersonation_rejected(self) -> None:
        """Un albarán firmado por un operador no valida con la clave pública de otro."""
        self.app.registrar_operador("otro_transporte", "OtroFrio!2026")
        lote_id = self.app.crear_lote(
            self.sesion, "Reactivos", 2.0, 8.0, "Laboratorio Sur", "Confidencial"
        )
        self.app.registrar_lectura(self.sesion, lote_id, "Entrega", 4.5)
        alb_id, _ = self.app.emitir_albaran(self.sesion, lote_id)

        ok, _ = self.app.verificar_albaran(alb_id, operador_esperado="otro_transporte")
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
    