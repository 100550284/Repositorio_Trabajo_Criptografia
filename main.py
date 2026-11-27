"""
Interfaz de línea de comandos (CLI) para demostrar CadenaFría en directo.
"""

from getpass import getpass

from app import AuthError, CadenaFriaApp, NotFoundError
from crypto_utils import CryptoError, IntegrityError


def _leer_float(prompt: str) -> float:
    valor = input(prompt).strip().replace(",", ".")
    return float(valor)


def run_cli() -> None:
    app = CadenaFriaApp(data_dir="data", verbose=True)
    sesion = None

    while True:
        print("\n=== CADENA FRÍA (Trazabilidad Segura) ===")
        if sesion is None:
            print("1. Registrar operador logístico")
            print("2. Iniciar sesión")
            print("3. Verificar albarán de entrega (público en destino)")
            print("0. Salir")
            opt = input("Opción: ").strip()

            try:
                if opt == "1":
                    user = input("Nombre de operador: ").strip()
                    pwd = getpass("Contraseña (min 10 chars, Mayús/minús/num/símbolo): ")
                    pwd2 = getpass("Repite la contraseña: ")
                    if pwd != pwd2:
                        raise AuthError("Las contraseñas no coinciden.")
                    app.registrar_operador(user, pwd)
                    print(f"Operador '{user}' registrado correctamente.")
                elif opt == "2":
                    user = input("Operador: ").strip()
                    pwd = getpass("Contraseña: ")
                    sesion = app.iniciar_sesion(user, pwd)
                    print(f"Sesión iniciada como '{sesion.usuario}'.")
                elif opt == "3":
                    alb_id = input("ID del albarán (ej. ALB-...): ").strip()
                    _, msg = app.verificar_albaran(alb_id)
                    print(f"Resultado: {msg}")
                elif opt == "0":
                    break
                else:
                    print("Opción no válida.")
            except (AuthError, CryptoError, IntegrityError, ValueError) as exc:
                print(f"[ERROR DE SEGURIDAD] {exc}")
        else:
            print(f"Operador activo: {sesion.usuario}")
            print("1. Registrar nuevo lote cifrado (AES-256-GCM)")
            print("2. Listar lotes")
            print("3. Consultar ficha confidencial de lote (descifrar)")
            print("4. Registrar lectura de temperatura (HMAC-SHA256)")
            print("5. Verificar cadena de telemetría de un lote (HMAC-SHA256)")
            print("6. Emitir y firmar albarán de entrega (ECDSA P-256)")
            print("7. Verificar albarán firmado")
            print("8. Cerrar sesión")
            opt = input("Opción: ").strip()

            try:
                if opt == "1":
                    producto = input("Producto (ej. Vacuna gripe Lote A): ")
                    t_min = _leer_float("Temperatura mínima permitida (°C, ej. 2): ")
                    t_max = _leer_float("Temperatura máxima permitida (°C, ej. 8): ")
                    cliente = input("Cliente destinatario (confidencial): ")
                    datos = input("Datos comerciales/fórmula/valor (confidencial): ")
                    lote_id = app.crear_lote(sesion, producto, t_min, t_max, cliente, datos)
                    print(f"Lote creado y cifrado con ID: {lote_id}")
                elif opt == "2":
                    lotes = app.listar_lotes(sesion)
                    if not lotes:
                        print("No hay lotes registrados.")
                    for l in lotes:
                        print(
                            f" - {l['lote_id']} | {l['producto']} | "
                            f"Rango: [{l['temp_min']} °C, {l['temp_max']} °C]"
                        )
                elif opt == "3":
                    lote_id = input("ID del lote: ").strip()
                    lote = app.leer_lote(sesion, lote_id)
                    print(f"\nLote: {lote['lote_id']} ({lote['producto']})")
                    print(f"Rango permitido: [{lote['temp_min']} °C, {lote['temp_max']} °C]")
                    print(f"Cliente destino: {lote['cliente_destino']}")
                    print(f"Datos confidenciales: {lote['datos_comerciales']}")
                elif opt == "4":
                    lote_id = input("ID del lote: ").strip()
                    ubicacion = input("Ubicación / parada (ej. Almacén Madrid): ")
                    temp = _leer_float("Temperatura medida (°C): ")
                    reg = app.registrar_lectura(sesion, lote_id, ubicacion, temp)
                    aviso = "OK (en rango)" if reg["en_rango"] else "ALERTA: CADENA DE FRÍO ROTA"
                    print(f"Lectura #{reg['seq']} guardada -> {reg['temperatura_c']} °C [{aviso}]")
                elif opt == "5":
                    lote_id = input("ID del lote: ").strip()
                    lecturas = app.verificar_telemetria(sesion, lote_id)
                    print(f"Integridad HMAC confirmada ({len(lecturas)} lecturas válidas):")
                    for r in lecturas:
                        marca = "OK" if r["en_rango"] else "FUERA DE RANGO"
                        print(f"  #{r['seq']} | {r['ubicacion']} | {r['temperatura_c']} °C | {marca}")
                elif opt == "6":
                    lote_id = input("ID del lote a entregar: ").strip()
                    alb_id, estado = app.emitir_albaran(sesion, lote_id)
                    print(f"Albarán firmado con ID: {alb_id} | Estado: {estado}")
                elif opt == "7":
                    alb_id = input("ID del albarán: ").strip()
                    _, msg = app.verificar_albaran(alb_id)
                    print(f"Resultado: {msg}")
                elif opt == "8":
                    sesion = None
                    print("Sesión cerrada (claves liberadas de memoria).")
                else:
                    print("Opción no válida.")
            except (AuthError, NotFoundError, CryptoError, IntegrityError, ValueError) as exc:
                print(f"[ERROR DE SEGURIDAD] {exc}")


if __name__ == "__main__":
    run_cli()
    