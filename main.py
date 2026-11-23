"""
Interfaz de línea de comandos (CLI) para demostrar VaultSign en directo.
"""

from getpass import getpass

from app import AuthError, NotFoundError, VaultSignApp
from crypto_utils import CryptoError, IntegrityError


def run_cli() -> None:
    app = VaultSignApp(data_dir="data", verbose=True)
    session = None

    while True:
        print("\n=== VAULTSIGN ===")
        if session is None:
            print("1. Registrar usuario")
            print("2. Iniciar sesión")
            print("3. Verificar documento firmado (público)")
            print("0. Salir")
            opt = input("Opción: ").strip()

            try:
                if opt == "1":
                    user = input("Usuario: ").strip()
                    pwd = getpass("Contraseña (min 10 chars, Mayús/minús/num/símbolo): ")
                    app.register_user(user, pwd)
                    print("Usuario registrado correctamente.")
                elif opt == "2":
                    user = input("Usuario: ").strip()
                    pwd = getpass("Contraseña: ")
                    session = app.login(user, pwd)
                    print(f"Sesión iniciada como '{session.username}'.")
                elif opt == "3":
                    sid = input("ID del documento firmado (signed_id): ").strip()
                    ok, msg = app.verify_signed_document(sid)
                    print(f"Resultado: {msg}")
                elif opt == "0":
                    break
                else:
                    print("Opción no válida.")
            except (AuthError, CryptoError, IntegrityError, ValueError) as exc:
                print(f"[ERROR DE SEGURIDAD] {exc}")
        else:
            print(f"Sesión activa: {session.username}")
            print("1. Crear y cifrar documento (AES-256-GCM)")
            print("2. Listar documentos")
            print("3. Leer y descifrar documento")
            print("4. Firmar documento digitalmente (ECDSA P-256)")
            print("5. Verificar documento firmado")
            print("6. Verificar integridad del log de auditoría (HMAC-SHA256)")
            print("7. Cerrar sesión")
            opt = input("Opción: ").strip()

            try:
                if opt == "1":
                    title = input("Título: ")
                    content = input("Contenido confidencial: ")
                    doc_id = app.save_document(session, title, content)
                    print(f"Documento guardado con ID: {doc_id}")
                elif opt == "2":
                    docs = app.list_documents(session)
                    if not docs:
                        print("Bóveda vacía.")
                    for d in docs:
                        print(f" - {d['doc_id']} | {d['title']} ({d['created_at']})")
                elif opt == "3":
                    doc_id = input("ID del documento: ").strip()
                    doc = app.read_document(session, doc_id)
                    print(f"\nTítulo: {doc['title']}\nContenido: {doc['content']}")
                elif opt == "4":
                    doc_id = input("ID del documento a firmar: ").strip()
                    sid = app.sign_document(session, doc_id)
                    print(f"Documento firmado. ID de firma: {sid}")
                elif opt == "5":
                    sid = input("ID de firma (signed_id): ").strip()
                    ok, msg = app.verify_signed_document(sid)
                    print(f"Resultado: {msg}")
                elif opt == "6":
                    count = app.verify_audit_log(session)
                    print(f"Integridad del log confirmada ({count} eventos válidos).")
                elif opt == "7":
                    session = None
                    print("Sesión cerrada (claves liberadas de memoria).")
                else:
                    print("Opción no válida.")
            except (AuthError, NotFoundError, CryptoError, IntegrityError, ValueError) as exc:
                print(f"[ERROR DE SEGURIDAD] {exc}")


if __name__ == "__main__":
    run_cli()
    