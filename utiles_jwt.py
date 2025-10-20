"""
jwt_utils_for_pentesting.py

Caja de herramientas para inspeccionar, procesar y verificar tokens y blobs serializados
orientada a laboratorios de pentesting. Funciones modulares pensadas para importar de forma
independiente (``from jwt_utils_for_pentesting import b64url_decode``) sin cargar todo el archivo.

Dependencias (instalar sólo las que necesites):
  - cryptography  -> verificación RSA/ECDSA: pip install cryptography
  - msgpack       -> detección/decodificación msgpack: pip install msgpack
  - cbor2         -> decodificación CBOR: pip install cbor2
  - pyjwt         -> utilidades JWT de alto nivel (opcional): pip install PyJWT

Nota de seguridad: NUNCA deserialices (pickle.loads, eval, etc.) blobs no confiables en un
entorno de producción o en tu máquina principal. Trata siempre los datos sospechosos como
binarios hasta que entiendas su naturaleza y, si hace falta, usa una VM aislada.

Autor: Asistente - Caja práctica para pentesting
"""

from typing import Tuple, Optional, Union, Any
import base64
import json
import zlib
import hmac
import hashlib
import binascii

# Dependencias opcionales importadas dentro de funciones para no obligar a instalarlas
__all__ = [
    'fix_b64_padding', 'b64url_decode', 'b64url_encode', 'guess_decode_text',
    'try_parse_json', 'parse_jwt', 'compute_hmac_sha256_signature', 'verify_hs256',
    'verify_rs256', 'try_decompress_deflate', 'decode_hex', 'detect_blob_type',
    'decode_possible_base64', 'safe_repr'
]

# ----------------------------- Utilidades básicas -----------------------------

def fix_b64_padding(s: str) -> str:
    """Ajusta padding para cadenas base64/base64url. Devuelve la cadena completada.

    Ejemplo:
        >>> fix_b64_padding('abc')
        'abc='  # (eso depende de la longitud)
    """
    return s + '=' * (-len(s) % 4)


def b64url_decode(s: str) -> bytes:
    """Decodifica una cadena base64url o base64 estándar a bytes.

    Reemplaza '-' -> '+' y '_' -> '/', arregla padding y hace base64.b64decode.
    Lanza binascii.Error si la entrada no es válida.
    """
    s = s.replace('-', '+').replace('_', '/')
    return base64.b64decode(fix_b64_padding(s))


def b64url_encode(b: bytes) -> str:
    """Codifica bytes a base64url sin padding (como en JWT)."""
    s = base64.b64encode(b).decode('ascii')
    return s.replace('+', '-').replace('/', '_').rstrip('=')


def guess_decode_text(b: bytes) -> str:
    """Intenta decodificar bytes a texto. Primero UTF-8, después Latin-1 (con reemplazo).

    Siempre devuelve una cadena; nunca lanza UnicodeDecodeError.
    """
    try:
        return b.decode('utf-8')
    except UnicodeDecodeError:
        return b.decode('latin-1', errors='replace')


def safe_repr(b: Union[bytes, str]) -> str:
    """Representación segura para imprimir blobs; muestra longitud y repr() limitado.

    Esto ayuda a inspeccionar sin volcar bytes binarios enormes a la consola.
    """
    if isinstance(b, bytes):
        snippet = repr(b[:256])
        return f'<bytes len={len(b)}> {snippet}...'
    else:
        snippet = repr(b[:512])
        return f'<str len={len(b)}> {snippet}...'


# ----------------------------- JSON y parsing -----------------------------

def try_parse_json(b: bytes) -> Optional[Any]:
    """Intenta parsear bytes como JSON y devuelve el objeto Python o None si falla."""
    try:
        return json.loads(guess_decode_text(b))
    except Exception:
        return None


# ----------------------------- JWT (parsing / utilidades) -----------------------------

def try_decompress_deflate(data: bytes) -> bytes:
    """Intenta descomprimir datos con zlib/DEFLATE.

    Algunos JWT usan 'zip': 'DEF' y esperan raw-deflate o zlib-wrapped data. Este helper
    prueba ambos modos y, si falla, devuelve los bytes sin modificar.
    """
    # Prueba zlib normal
    try:
        return zlib.decompress(data)
    except Exception:
        pass
    # Prueba raw deflate (negativa de wbits)
    try:
        return zlib.decompress(data, -zlib.MAX_WBITS)
    except Exception:
        pass
    # No se pudo descomprimir; devolvemos original
    return data


def parse_jwt(token: str) -> Tuple[Optional[dict], Optional[Union[dict, str, bytes]], Optional[bytes]]:
    """Parsea un JWT (sin verificar) y devuelve (header_dict, payload, signature_bytes).

    - header_dict: dict si parseable, sino None
    - payload: dict (si JSON), str (si texto) o bytes (si binario no parseable)
    - signature_bytes: bytes de la firma (None si la parte no es base64 válida)

    No lanza a menos que el token no tenga 3 partes.
    """
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('Formato JWT inválido: debe contener 3 partes separadas por puntos')

    h_b, p_b, sig_b = None, None, None
    # decodifica header y payload con tolerancia
    try:
        h_b = b64url_decode(parts[0])
    except Exception:
        h_b = None
    try:
        p_b = b64url_decode(parts[1])
    except Exception:
        p_b = None
    try:
        sig_b = b64url_decode(parts[2])
    except Exception:
        sig_b = None

    header = try_parse_json(h_b) if h_b is not None else None

    # Si header indica compresión, descomprime payload antes de parsear
    if isinstance(header, dict) and header.get('zip', '').upper() == 'DEF' and p_b is not None:
        p_b = try_decompress_deflate(p_b)

    payload = None
    if p_b is not None:
        payload = try_parse_json(p_b) or guess_decode_text(p_b)

    return (header, payload, sig_b)


def compute_hmac_sha256_signature(header_b64: str, payload_b64: str, key: bytes) -> bytes:
    """Calcula HMAC-SHA256 sobre 'header_b64.payload_b64' y devuelve los bytes de la firma.

    IMPORTANTE: usar exactamente las partes base64 originales al verificar/falsificar firmas.
    """
    msg = (header_b64 + '.' + payload_b64).encode('ascii')
    return hmac.new(key, msg, hashlib.sha256).digest()


def verify_hs256(token: str, key: Union[str, bytes]) -> bool:
    """Verifica un JWT HS256 comparando la firma con la clave proporcionada.

    - key: bytes o str (si str, se codifica en UTF-8)
    - devuelve True si la firma coincide, False en otro caso.
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    header_b64, payload_b64, sig_b64 = token.split('.')
    expected = compute_hmac_sha256_signature(header_b64, payload_b64, key)
    try:
        given = b64url_decode(sig_b64)
    except Exception:
        return False
    # Uso compare_digest para evitar diferencias temporales
    return hmac.compare_digest(expected, given)


# ----------------------------- Firma asimétrica (RSA/ECDSA) -----------------------------

def verify_rs256(token: str, public_pem: bytes) -> bool:
    """Verifica un JWT RS256 usando una clave pública en formato PEM.

    Requiere `cryptography`. La función importa `cryptography` bajo demanda para no forzar
    la dependencia si no se necesita.
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature
    except Exception as e:
        raise ImportError('cryptography requerida para verify_rs256: pip install cryptography') from e

    header_b64, payload_b64, sig_b64 = token.split('.')
    signed = (header_b64 + '.' + payload_b64).encode('ascii')
    try:
        sig = b64url_decode(sig_b64)
    except Exception:
        return False

    pub = serialization.load_pem_public_key(public_pem)
    try:
        pub.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# ----------------------------- Otros decodificadores útiles -----------------------------

def decode_hex(s: str) -> bytes:
    """Decodifica una cadena hexadecimal a bytes. Lanza ValueError si no válida."""
    # Permitir espacios y 0x
    s2 = s.strip().lower()
    if s2.startswith('0x'):
        s2 = s2[2:]
    s2 = s2.replace(' ', '')
    return bytes.fromhex(s2)


def decode_possible_base64(s: str) -> Optional[bytes]:
    """Intenta decodificar una cadena como base64/base64url. Devuelve bytes o None.

    Útil para detectar rápidamente si un campo es base64 sin lanzar excepciones arriba.
    """
    try:
        return b64url_decode(s)
    except Exception:
        try:
            return base64.b64decode(fix_b64_padding(s))
        except Exception:
            return None


# ----------------------------- Detección simple de formatos -----------------------------

def detect_blob_type(b: bytes) -> str:
    """Intenta inferir el tipo de un blob por magic numbers o patrones sencillos.

    Devuelve una cadena corta indicando la suposición: 'json', 'jwt', 'msgpack', 'cbor', 'elf',
    'pe', 'gzip', 'zlib', 'text', 'unknown', 'hex', 'base64'. No es exhaustivo pero útil.
    """
    # UTF-8 imprimible -> probable texto/JSON
    try:
        txt = b.decode('utf-8')
        # JWT heurística: tres partes separadas por '.' y cada parte base64url-like
        if txt.count('.') == 2:
            p0, p1, p2 = txt.split('.')
            # comprobación básica: solo caracteres válidos base64url
            import re
            if re.fullmatch(r'[A-Za-z0-9\-_]+=*', p0) and re.fullmatch(r'[A-Za-z0-9\-_]+=*', p1):
                return 'jwt'
        # JSON heurística
        stripped = txt.lstrip()
        if stripped.startswith('{') or stripped.startswith('['):
            return 'json'
        # hex detect: mayoría caracteres hex y espacios
        if all(c in '0123456789abcdefABCDEF \n\r\t' for c in txt[:256]):
            return 'hex'
        # fallback texto
        return 'text'
    except UnicodeDecodeError:
        pass

    # Magic bytes
    if b.startswith(b'\x1f\x8b'):
        return 'gzip'
    if b[:4] == b'PK\x03\x04':
        return 'zip'
    if b.startswith(b'\x7fELF'):
        return 'elf'
    if b[:2] == b'MZ':
        return 'pe'
    # CBOR magic: no hay magic fijo fácil, intentaremos msgpack detect
    # msgpack suele no tener magic, pero podemos intentar una decodificación segura
    try:
        import msgpack
        try:
            msgpack.unpackb(b, raw=False)
            return 'msgpack'
        except Exception:
            pass
    except Exception:
        pass

    # zlib header
    if b[:2] == b'\x78\x9c' or b[:2] == b'\x78\x01' or b[:2] == b'\x78\xda':
        return 'zlib'

    return 'unknown'


# ----------------------------- Detección y decodificación automática básica -----------------------------

def detect_and_parse_blob(blob: Union[str, bytes]) -> dict:
    """Intento razonable de detectar y decodificar un blob.

    Devuelve un dict con campos útiles: 'type', 'decoded' (si procede), 'json' (si parseable),
    'notes'. No garantiza interpretación correcta, es una ayuda para diagnóstico.
    """
    if isinstance(blob, str):
        raw = blob.encode('utf-8')
    else:
        raw = blob

    out = {'type': None, 'decoded': None, 'json': None, 'notes': []}
    t = detect_blob_type(raw)
    out['type'] = t

    if t == 'jwt' and isinstance(blob, str):
        try:
            h, p, s = parse_jwt(blob)
            out['decoded'] = {'header': h, 'payload': p, 'signature': safe_repr(s) if s is not None else None}
            out['json'] = p if isinstance(p, dict) else None
            return out
        except Exception as e:
            out['notes'].append(f'Error parsing JWT: {e}')

    if t == 'json':
        try:
            out['json'] = json.loads(blob.decode('utf-8'))
            out['decoded'] = out['json']
            return out
        except Exception:
            out['notes'].append('JSON detectado pero no parseable con UTF-8')

    if t == 'hex':
        try:
            d = decode_hex(blob.decode('utf-8'))
            out['decoded'] = safe_repr(d)
            # intenta re-detección
            out['notes'].append('Decodificado de hex, re-ejecutar detect_blob_type sobre el resultado si es necesario')
            return out
        except Exception as e:
            out['notes'].append(f'No fue posible decodificar hex: {e}')

    # si parece base64
    try:
        maybe_b64 = decode_possible_base64(blob.decode('utf-8')) if isinstance(blob, (bytes, str)) else None
        if maybe_b64:
            out['notes'].append('Se detectó base64/base64url decodificable (posible JWT u otro blob)')
            out['decoded'] = safe_repr(maybe_b64)
            # intentar reconocer qué es el contenido
            out['type'] = detect_blob_type(maybe_b64)
            # si es JSON
            try:
                out['json'] = json.loads(guess_decode_text(maybe_b64))
            except Exception:
                pass
            return out
    except Exception:
        pass

    out['notes'].append('No se pudo decodificar con heurísticas básicas')
    out['decoded'] = safe_repr(raw)
    return out


# ----------------------------- Recomendaciones de uso -----------------------------
# Importa solo las funciones que necesites por ejemplo:
#   from jwt_utils_for_pentesting import parse_jwt, verify_hs256
#
# Usa `detect_and_parse_blob` como primer paso de diagnóstico y luego funciones concretas
# para verificación o decodificación más profunda.


if __name__ == '__main__':
    # Pequeño demo: no ejecutar en entorno con datos sensibles
    example_jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' \
                  'eyJ1c2VyIjoiamRvZSIsImlhdCI6MTYwOTk5OTk5OX0.' \
                  'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
    print('Ejecutando demo rápido (parse_jwt):')
    try:
        header, payload, sig = parse_jwt(example_jwt)
        print('header=', header)
        print('payload=', payload)
        print('signature=', safe_repr(sig))
    except Exception as e:
        print('Demo falló:', e)
