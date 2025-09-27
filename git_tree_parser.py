# tree_parser.py
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "tree.raw"
oid_len = 20  # pon 32 si sabes que el repo es SHA-256

data = open(path, "rb").read()

# --- 1) Saltar cabecera "tree <size>\0" si existe ---
i = 0
if data.startswith(b"tree "):
    j = data.find(b"\x00", 0)
    if j == -1:
        raise RuntimeError("Cabecera 'tree <size>\\0' corrupta.")
    i = j + 1  # empezamos justo después del NUL

# --- 2) Parsear entradas ---
entries = []
while i < len(data):
    # modo (ascii) hasta espacio
    j = data.find(b" ", i)
    if j == -1: raise RuntimeError("No se encontró espacio tras el modo.")
    mode = data[i:j].decode("ascii")
    i = j + 1

    # nombre hasta NUL
    j = data.find(b"\x00", i)
    if j == -1: raise RuntimeError("No se encontró NUL tras el nombre.")
    name = data[i:j].decode("utf-8", errors="surrogateescape")
    i = j + 1

    # id binario
    oid = data[i:i+oid_len]
    if len(oid) != oid_len:
        # ¿quizá era SHA-256? reintenta automáticamente
        if oid_len == 20 and (len(data) - (i)) >= 32:
            oid_len = 32
            oid = data[i:i+oid_len]
        else:
            raise RuntimeError("Longitud de OID inconsistente.")
    i += oid_len

    entries.append((mode, oid.hex(), name))

# --- 3) Mostrar ---
for mode, oid, name in entries:
    tipo = {"040000":"tree", "100644":"blob", "100755":"blob*", "120000":"link"}.get(mode, "?")
    print(f"{mode}\t{tipo}\t{oid}\t{name}")
