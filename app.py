"""
Lógica principal de CadenaFría: gestión de operadores logísticos, lotes con datos
confidenciales cifrados (AES-256-GCM), telemetría de temperatura encadenada
(HMAC-SHA256) y albaranes de entrega firmados digitalmente (ECDSA P-256).
"""

import base64
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import crypto_utils as cu
from storage import SecureStorage


class AuthError(Exception):
    """Error de autenticación o registro de operador."""


class NotFoundError(Exception):
    """Lote o albarán no encontrado."""


@dataclass
class SesionOperador:
    """Claves derivadas mantenidas únicamente en memoria RAM durante la sesión."""
    usuario: str
    enc_key: bytes
    mac_key: bytes
    private_key_pem: bytes


class CadenaFriaApp:
    """Aplicación principal de trazabilidad segura de cadena de frío."""

    def __init__(self, data_dir: str = "data", verbose: bool = True) -> None:
        self.storage = SecureStorage(data_dir)
        self.verbose = verbose

    def _debug(self, message: str) -> None:
        """Muestra trazas de depuración criptográfica sin revelar jamás secretos."""
        if self.verbose:
            print(f"[CRYPTO-LOG] {message}")

    @staticmethod
    def _validate_username(usuario: str) -> None:
        if not re.fullmatch(r"[a-zA-Z0-9_]{3,24}", usuario):
            raise AuthError(
                "El nombre de operador debe tener entre 3 y 24 caracteres alfanuméricos o '_'."
            )

    @staticmethod
    def _canonical_json(payload: dict) -> bytes:
        """Serialización JSON determinista para cálculo de HMAC y firma digital."""
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _build_lote_aad(
        operador: str,
        lote_id: str,
        version: int,
        producto: str,
        temp_min: float,
        temp_max: float,
    ) -> bytes:
        """
        Construye el AAD de AES-GCM vinculando al lote sus límites térmicos permitidos.
        Si un atacante altera temp_min o temp_max en disco, el descifrado falla.
        """
        return (
            f"{operador}|{lote_id}|v{version}|{producto}|{temp_min:.2f}|{temp_max:.2f}"
        ).encode("utf-8")

    # ------------------------------------------------------------------
    # 1. REGISTRO Y AUTENTICACIÓN DE OPERADORES
    # ------------------------------------------------------------------
    def registrar_operador(self, usuario: str, password: str) -> None:
        self._validate_username(usuario)
        cu.validate_password_strength(password)

        operadores = self.storage.load_json(self.storage.operadores_file(), {})
        if usuario in operadores:
            raise AuthError(f"El operador '{usuario}' ya está registrado.")

        # Sales independientes de 128 bits para login y derivación de claves
        salt_auth = cu.generate_random_bytes(cu.SALT_LEN)
        salt_kdf = cu.generate_random_bytes(cu.SALT_LEN)
        auth_hash = cu.derive_key_scrypt(password, salt_auth)

        # Derivación en memoria para proteger la clave privada ECDSA con AES-256-GCM
        master_key = cu.derive_key_scrypt(password, salt_kdf)
        subkeys = cu.derive_subkeys(master_key, salt_kdf)

        priv_pem, pub_pem = cu.generate_ecdsa_keypair()
        priv_aad = f"ecdsa-privkey|{usuario}".encode("utf-8")
        encrypted_priv = cu.aes_gcm_encrypt(subkeys["keywrap_key"], priv_pem, priv_aad)

        operadores[usuario] = {
            "kdf": f"scrypt(N={cu.SCRYPT_N},r={cu.SCRYPT_R},p={cu.SCRYPT_P})",
            "salt_auth": base64.b64encode(salt_auth).decode("ascii"),
            "auth_hash": base64.b64encode(auth_hash).decode("ascii"),
            "salt_kdf": base64.b64encode(salt_kdf).decode("ascii"),
            "ecdsa_curve": "SECP256R1",
            "public_key_pem": pub_pem,
            "encrypted_private_key": encrypted_priv,
            "creado_en": datetime.now(timezone.utc).isoformat(),
        }
        self.storage.save_json(self.storage.operadores_file(), operadores)
        self.storage.save_json(self.storage.lotes_file(usuario), {})
        self.storage.save_json(self.storage.telemetria_file(usuario), {})

        self._debug(
            f"Operador '{usuario}' registrado | Auth: scrypt (salt 128b) | "
            f"Firma: ECDSA P-256 | Clave privada cifrada con AES-256-GCM "
            f"(nonce={encrypted_priv['nonce'][:12]}...)"
        )

    def iniciar_sesion(self, usuario: str, password: str) -> SesionOperador:
        operadores = self.storage.load_json(self.storage.operadores_file(), {})
        record = operadores.get(usuario)
        if not record:
            raise AuthError("Credenciales inválidas.")

        salt_auth = base64.b64decode(record["salt_auth"])
        expected_hash = base64.b64decode(record["auth_hash"])

        if not cu.verify_password(password, salt_auth, expected_hash):
            self._debug(f"Autenticación FALLIDA para '{usuario}' (hash scrypt no coincide).")
            raise AuthError("Credenciales inválidas.")

        # Reconstrucción de las 3 subclaves en RAM mediante scrypt + HKDF-SHA256
        salt_kdf = base64.b64decode(record["salt_kdf"])
        master_key = cu.derive_key_scrypt(password, salt_kdf)
        subkeys = cu.derive_subkeys(master_key, salt_kdf)

        # Descifrado y autenticación de la clave privada ECDSA del operador
        enc_priv = record["encrypted_private_key"]
        priv_aad = f"ecdsa-privkey|{usuario}".encode("utf-8")
        priv_pem = cu.aes_gcm_decrypt(
            subkeys["keywrap_key"],
            enc_priv["nonce"],
            enc_priv["ciphertext"],
            enc_priv["tag"],
            priv_aad,
        )

        self._debug(
            f"Login OK para '{usuario}' | Subclaves HKDF-SHA256 (256b) en RAM | "
            f"Clave privada ECDSA descifrada correctamente."
        )
        return SesionOperador(
            usuario=usuario,
            enc_key=subkeys["enc_key"],
            mac_key=subkeys["mac_key"],
            private_key_pem=priv_pem,
        )

    # ------------------------------------------------------------------
    # 2. GESTIÓN Y CIFRADO DE LOTES (AES-256-GCM + AAD TÉRMICO)
    # ------------------------------------------------------------------
    def crear_lote(
        self,
        sesion: SesionOperador,
        producto: str,
        temp_min: float,
        temp_max: float,
        cliente_destino: str,
        datos_comerciales: str,
    ) -> str:
        """
        Registra un lote cifrando los datos comerciales sensibles (cliente, fórmula,
        valor o ruta) con AES-256-GCM y autenticando el rango térmico en el AAD.
        """
        if not producto.strip() or not cliente_destino.strip() or not datos_comerciales.strip():
            raise ValueError("Producto, cliente y datos confidenciales son obligatorios.")

        temp_min = round(float(temp_min), 2)
        temp_max = round(float(temp_max), 2)
        if temp_min >= temp_max:
            raise ValueError("La temperatura mínima debe ser estrictamente menor que la máxima.")

        lote_id = f"LOT-{secrets.token_hex(4).upper()}"
        version = 1
        aad = self._build_lote_aad(
            sesion.usuario, lote_id, version, producto.strip(), temp_min, temp_max
        )
        plaintext = self._canonical_json(
            {
                "cliente_destino": cliente_destino.strip(),
                "datos_comerciales": datos_comerciales.strip(),
            }
        )
        encrypted = cu.aes_gcm_encrypt(sesion.enc_key, plaintext, aad)

        lotes = self.storage.load_json(self.storage.lotes_file(sesion.usuario), {})
        lotes[lote_id] = {
            "lote_id": lote_id,
            "operador": sesion.usuario,
            "version": version,
            "producto": producto.strip(),
            "temp_min": temp_min,
            "temp_max": temp_max,
            "creado_en": datetime.now(timezone.utc).isoformat(),
            **encrypted,
        }
        self.storage.save_json(self.storage.lotes_file(sesion.usuario), lotes)

        # Inicializa la cadena de telemetría vacía para el lote
        telemetria = self.storage.load_json(self.storage.telemetria_file(sesion.usuario), {})
        telemetria[lote_id] = []
        self.storage.save_json(self.storage.telemetria_file(sesion.usuario), telemetria)

        self._debug(
            f"Lote '{lote_id}' cifrado | Algoritmo: AES-256-GCM (256b) | "
            f"Rango AAD: [{temp_min:.2f} °C, {temp_max:.2f} °C] | "
            f"Nonce(96b)={encrypted['nonce']} | Tag(128b)={encrypted['tag']}"
        )
        return lote_id

    def leer_lote(self, sesion: SesionOperador, lote_id: str) -> Dict[str, Any]:
        """Descifra los datos confidenciales de un lote verificando su tag GCM y AAD."""
        lotes = self.storage.load_json(self.storage.lotes_file(sesion.usuario), {})
        entry = lotes.get(lote_id)
        if not entry:
            raise NotFoundError(f"No existe el lote '{lote_id}'.")

        aad = self._build_lote_aad(
            sesion.usuario,
            entry["lote_id"],
            entry["version"],
            entry["producto"],
            float(entry["temp_min"]),
            float(entry["temp_max"]),
        )
        plaintext = cu.aes_gcm_decrypt(
            sesion.enc_key,
            entry["nonce"],
            entry["ciphertext"],
            entry["tag"],
            aad,
        )
        confidencial = json.loads(plaintext.decode("utf-8"))

        self._debug(
            f"Lote '{lote_id}' descifrado y autenticado OK | "
            f"Algoritmo: AES-256-GCM | Límites térmicos en AAD verificados."
        )
        return {
            "lote_id": entry["lote_id"],
            "producto": entry["producto"],
            "temp_min": float(entry["temp_min"]),
            "temp_max": float(entry["temp_max"]),
            "cliente_destino": confidencial["cliente_destino"],
            "datos_comerciales": confidencial["datos_comerciales"],
            "creado_en": entry["creado_en"],
        }

    def listar_lotes(self, sesion: SesionOperador) -> List[Dict[str, Any]]:
        lotes = self.storage.load_json(self.storage.lotes_file(sesion.usuario), {})
        return [
            {
                "lote_id": item["lote_id"],
                "producto": item["producto"],
                "temp_min": item["temp_min"],
                "temp_max": item["temp_max"],
                "creado_en": item["creado_en"],
            }
            for item in lotes.values()
        ]

    # ------------------------------------------------------------------
    # 3. TELEMETRÍA DE TEMPERATURA ENCADENADA (HMAC-SHA256)
    # ------------------------------------------------------------------
    def registrar_lectura(
        self,
        sesion: SesionOperador,
        lote_id: str,
        ubicacion: str,
        temperatura_c: float,
    ) -> Dict[str, Any]:
        """
        Añade una lectura de temperatura a la cadena HMAC-SHA256 del lote.
        Antes de escribir, verifica la integridad del lote (AES-GCM) y de toda
        la cadena previa (HMAC-SHA256) para impedir añadir sobre datos corruptos.
        """
        if not ubicacion.strip():
            raise ValueError("La ubicación de la parada no puede estar vacía.")

        lote = self.leer_lote(sesion, lote_id)
        lecturas = self.verificar_telemetria(sesion, lote_id)

        temp_val = round(float(temperatura_c), 2)
        en_rango = lote["temp_min"] <= temp_val <= lote["temp_max"]
        seq = len(lecturas) + 1
        prev_hmac = lecturas[-1]["hmac"] if lecturas else ("0" * 64)

        body = {
            "seq": seq,
            "lote_id": lote_id,
            "operador": sesion.usuario,
            "ubicacion": ubicacion.strip(),
            "temperatura_c": temp_val,
            "en_rango": en_rango,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prev_hmac": prev_hmac,
        }
        tag_hex = cu.compute_hmac_sha256(sesion.mac_key, self._canonical_json(body))
        registro = {**body, "hmac": tag_hex}

        telemetria = self.storage.load_json(self.storage.telemetria_file(sesion.usuario), {})
        telemetria.setdefault(lote_id, []).append(registro)
        self.storage.save_json(self.storage.telemetria_file(sesion.usuario), telemetria)

        estado_txt = "EN RANGO" if en_rango else "ALERTA FUERA DE RANGO"
        self._debug(
            f"Lectura #{seq} ({lote_id}: {temp_val:.2f} °C - {estado_txt}) protegida | "
            f"Algoritmo: HMAC-SHA256 (clave 256b) | MAC={tag_hex[:16]}..."
        )
        return registro

    def verificar_telemetria(self, sesion: SesionOperador, lote_id: str) -> List[Dict[str, Any]]:
        """
        Verifica toda la cadena HMAC-SHA256 de lecturas de un lote: detecta
        alteración de temperaturas, borrado de alertas, reordenamiento o replay.
        """
        lotes = self.storage.load_json(self.storage.lotes_file(sesion.usuario), {})
        if lote_id not in lotes:
            raise NotFoundError(f"No existe el lote '{lote_id}'.")

        telemetria = self.storage.load_json(self.storage.telemetria_file(sesion.usuario), {})
        lecturas = telemetria.get(lote_id, [])
        expected_prev = "0" * 64

        for idx, entry in enumerate(lecturas, start=1):
            if entry.get("seq") != idx:
                raise cu.IntegrityError(
                    f"Secuencia de telemetría alterada en lectura {idx} (posible borrado o replay)."
                )
            if entry.get("lote_id") != lote_id or entry.get("operador") != sesion.usuario:
                raise cu.IntegrityError(
                    f"Lectura {idx} no pertenece al lote '{lote_id}' o al operador actual."
                )
            if entry.get("prev_hmac") != expected_prev:
                raise cu.IntegrityError(
                    f"Cadena HMAC rota en lectura {idx} (posible borrado o reordenamiento)."
                )

            body = {
                "seq": entry["seq"],
                "lote_id": entry["lote_id"],
                "operador": entry["operador"],
                "ubicacion": entry["ubicacion"],
                "temperatura_c": entry["temperatura_c"],
                "en_rango": entry["en_rango"],
                "timestamp": entry["timestamp"],
                "prev_hmac": entry["prev_hmac"],
            }
            cu.verify_hmac_sha256(sesion.mac_key, self._canonical_json(body), entry["hmac"])
            expected_prev = entry["hmac"]

        self._debug(
            f"Telemetría de '{lote_id}' verificada OK ({len(lecturas)} lecturas) | "
            f"Algoritmo: HMAC-SHA256 (clave 256b)."
        )
        return lecturas

    # ------------------------------------------------------------------
    # 4. FIRMA DIGITAL DE ALBARANES DE CONFORMIDAD (ECDSA P-256 + SHA-256)
    # ------------------------------------------------------------------
    def emitir_albaran(self, sesion: SesionOperador, lote_id: str) -> Tuple[str, str]:
        """
        Verifica el lote (AES-GCM) y toda su telemetría (HMAC-SHA256) y emite un
        albarán de entrega firmado con ECDSA P-256 verificable públicamente en destino.
        """
        lote = self.leer_lote(sesion, lote_id)
        lecturas = self.verificar_telemetria(sesion, lote_id)
        if not lecturas:
            raise ValueError(
                "No se puede emitir albarán sin al menos una lectura de temperatura registrada."
            )

        temperaturas = [float(r["temperatura_c"]) for r in lecturas]
        todas_en_rango = all(
            lote["temp_min"] <= temp <= lote["temp_max"] for temp in temperaturas
        )
        estado_cadena = "CADENA_FRIA_INTACTA" if todas_en_rango else "CADENA_FRIA_ROTA"
        albaran_id = f"ALB-{secrets.token_hex(4).upper()}"

        resumen_telemetria = {
            "num_lecturas": len(lecturas),
            "temp_min_registrada": min(temperaturas),
            "temp_max_registrada": max(temperaturas),
            "estado_cadena": estado_cadena,
            "paradas": [
                {
                    "seq": r["seq"],
                    "ubicacion": r["ubicacion"],
                    "temperatura_c": r["temperatura_c"],
                    "timestamp": r["timestamp"],
                }
                for r in lecturas
            ],
            "ultimo_hmac_cadena": lecturas[-1]["hmac"],
        }

        payload = {
            "albaran_id": albaran_id,
            "operador": sesion.usuario,
            "lote_id": lote["lote_id"],
            "producto": lote["producto"],
            "cliente_destino": lote["cliente_destino"],
            "rango_permitido_c": [lote["temp_min"], lote["temp_max"]],
            "resumen_telemetria": resumen_telemetria,
            "hash_resumen_sha256": cu.sha256_hex(self._canonical_json(resumen_telemetria)),
            "emitido_en": datetime.now(timezone.utc).isoformat(),
            "firma_nonce": secrets.token_hex(16),  # Evita albaranes firmados idénticos
        }
        firma_b64 = cu.sign_ecdsa_sha256(
            sesion.private_key_pem, self._canonical_json(payload)
        )

        albaranes = self.storage.load_json(self.storage.albaranes_file(), {})
        albaranes[albaran_id] = {
            "algorithm": "ECDSA-SECP256R1-SHA256",
            "payload": payload,
            "firma": firma_b64,
        }
        self.storage.save_json(self.storage.albaranes_file(), albaranes)

        self._debug(
            f"Albarán '{albaran_id}' firmado ({estado_cadena}) | "
            f"Algoritmo: ECDSA P-256 (256b) + SHA-256 | Firma={firma_b64[:20]}..."
        )
        return albaran_id, estado_cadena

    def verificar_albaran(
        self, albaran_id: str, operador_esperado: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Verifica un albarán de entrega usando la clave pública del transportista.
        Operación pública: no requiere inicio de sesión ni conocer secretos.
        """
        albaranes = self.storage.load_json(self.storage.albaranes_file(), {})
        record = albaranes.get(albaran_id)
        if not record:
            return False, f"No existe el albarán '{albaran_id}'."

        payload = record["payload"]
        operador = operador_esperado or payload.get("operador")

        operadores = self.storage.load_json(self.storage.operadores_file(), {})
        op_record = operadores.get(operador)
        if not op_record:
            return False, f"No se encontró la clave pública del operador '{operador}'."

        # 1. Comprobación de integridad del resumen de telemetría frente a SHA-256
        recomputed_hash = cu.sha256_hex(self._canonical_json(payload["resumen_telemetria"]))
        if recomputed_hash != payload.get("hash_resumen_sha256"):
            self._debug(
                f"Albarán '{albaran_id}' RECHAZADO: resumen térmico alterado respecto a SHA-256."
            )
            return False, "RECHAZADO: los datos de temperatura del albarán han sido manipulados."

        # 2. Verificación criptográfica ECDSA con la clave pública del operador
        es_valida = cu.verify_ecdsa_sha256(
            op_record["public_key_pem"],
            self._canonical_json(payload),
            record["firma"],
        )
        if not es_valida:
            self._debug(
                f"Albarán '{albaran_id}' RECHAZADO | Algoritmo: ECDSA-SECP256R1-SHA256 | "
                f"Operador probado: '{operador}'."
            )
            return False, "RECHAZADO: firma digital inválida, manipulada o de otro operador."

        resumen = payload["resumen_telemetria"]
        self._debug(
            f"Albarán '{albaran_id}' VÁLIDO | Algoritmo: ECDSA-SECP256R1-SHA256 (256b) | "
            f"Firmante: '{operador}' | Estado: {resumen['estado_cadena']}."
        )
        return (
            True,
            f"VÁLIDO: firmado por '{operador}' | Producto: {payload['producto']} | "
            f"Estado: {resumen['estado_cadena']} "
            f"(Min: {resumen['temp_min_registrada']} °C, Max: {resumen['temp_max_registrada']} °C, "
            f"{resumen['num_lecturas']} lecturas).",
        )
    