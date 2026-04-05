"""
Buzon Mudo — Intercambio de Archivos de Conocimiento Cero

Este servidor es deliberadamente "ciego". Opera bajo el principio
Zero-Knowledge: solo almacena y reenvía datos cifrados que no puede leer.

    EMISOR  → genera clave AES-256 en su navegador
            → cifra texto y archivo localmente (client-side)
            → envía "basura digital" cifrada a este servidor
            → recibe un ID
            → comparte el ID (link) Y la clave con el receptor por separado

    SERVIDOR → almacena basura cifrada opaca
             → no conoce, no recibe y no puede inferir la clave

    RECEPTOR → recibe la basura cifrada desde el servidor
             → descifra en SU propio navegador con la clave que recibió
             → el servidor nunca supo qué había adentro

¿Por qué importa?
    Si este servidor es comprometido o recibe una orden judicial,
    los datos almacenados son ilegibles. No existe "llave maestra".

AUDITORÍA:
    Busca en este archivo cualquier función de descifrado. No encontrarás
    ninguna. La única operación sobre los datos es INSERT y SELECT.
"""

import os
import hashlib
import secrets
import base64
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, render_template, abort
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ─── Límite global de tamaño de petición ──────────────────────────────────────
# Flask rechaza automáticamente con 413 cualquier petición que supere este límite.
# Esto previene ataques de agotamiento de memoria (DoS por upload masivo).
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB


# ─── Configuración (viene del archivo .env, nunca del código) ─────────────────
DB_CONFIG = {
    'dbname':   os.getenv('DB_NAME',     'buzonmudo'),
    'user':     os.getenv('DB_USER',     'postgres'),
    'password': os.getenv('DB_PASSWORD', ''),
    'host':     os.getenv('DB_HOST',     'localhost'),
    'port':     os.getenv('DB_PORT',     '5432'),
}

SITE_NAME         = os.getenv('SITE_NAME',        'Buzon Mudo')
GITHUB_LINK       = os.getenv('GITHUB_LINK',       '')
DROP_EXPIRY_HOURS = int(os.getenv('DROP_EXPIRY_HOURS', '72'))

# Nombres de pantalla para los tickers más comunes.
# Si el usuario agrega un ticker no listado aquí, se muestra el ticker en mayúsculas.
_CRYPTO_DISPLAY_NAMES = {
    'XMR':  'Monero',
    'BTC':  'Bitcoin',
    'ETH':  'Ethereum',
    'LTC':  'Litecoin',
    'USDT': 'Tether (USDT)',
    'USDC': 'USD Coin (USDC)',
}


# ─── Base de datos ─────────────────────────────────────────────────────────────

def get_db():
    """Abre y retorna una conexión fresca a PostgreSQL."""
    return psycopg2.connect(**DB_CONFIG)


# ─── Utilidades ────────────────────────────────────────────────────────────────

def hash_ip(ip_str: str) -> str:
    """
    Transforma una IP en un hash SHA-256 unidireccional.

    Por qué no guardamos la IP real:
        Queremos poder detectar spam (muchos drops desde la misma fuente)
        sin violar la privacidad del emisor. Un hash SHA-256 nos permite
        comparar IPs sin poder revertir el hash a la IP original.

    "Unidireccional" = imposible de revertir matemáticamente.
    """
    return hashlib.sha256(ip_str.encode('utf-8')).hexdigest()


def get_client_ip() -> str:
    """
    Extrae la IP real del cliente, considerando proxies inversos (Nginx, etc.).
    X-Forwarded-For puede contener una cadena de IPs; la primera es la del cliente.
    """
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


def _validate_id(drop_id: str):
    """
    Valida el formato del ID para prevenir path traversal e inyecciones.
    secrets.token_urlsafe usa solo [A-Za-z0-9_-], máx 43 chars para 32 bytes.
    Abortamos con 404 ante cualquier ID sospechoso.
    """
    if not drop_id or len(drop_id) > 64:
        abort(404)
    allowed = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_')
    if not all(c in allowed for c in drop_id):
        abort(404)


# ─── Context processor global ──────────────────────────────────────────────────

@app.context_processor
def inject_crypto():
    """
    Inyecta la lista de criptomonedas aceptadas en TODOS los templates
    automáticamente, sin necesidad de pasarla manualmente en cada ruta.

    Lee CRYPTO_RECEIVE del .env (ej: "XMR,BTC") y para cada ticker
    busca {TICKER}_ADDRESS. Solo incluye los que tienen dirección configurada.

    Resultado disponible en los templates como la variable `cryptos`:
        [{ ticker: "XMR", name: "Monero", address: "4Ab..." }, ...]
    """
    raw = os.getenv('CRYPTO_RECEIVE', '')
    tickers = [t.strip().upper() for t in raw.split(',') if t.strip()]
    cryptos = []
    for ticker in tickers:
        address = os.getenv(f'{ticker}_ADDRESS', '').strip()
        if address:
            cryptos.append({
                'ticker':  ticker,
                'name':    _CRYPTO_DISPLAY_NAMES.get(ticker, ticker),
                'address': address,
            })
    return {'cryptos': cryptos}


# ─── Rutas ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Página principal: explicación de la tecnología y formulario de subida."""
    return render_template('index.html', site_name=SITE_NAME, github_link=GITHUB_LINK)


@app.route('/upload', methods=['POST'])
def upload():
    """
    Recibe el drop YA CIFRADO desde el navegador del emisor.

    ╔══════════════════════════════════════════════════════════╗
    ║  NOTA DE AUDITORÍA — LA CLAVE NO PASA POR AQUÍ          ║
    ║                                                          ║
    ║  Los datos que llegan a este endpoint están cifrados     ║
    ║  con AES-256-GCM. La clave de cifrado fue generada y     ║
    ║  retenida en el navegador del emisor. Este servidor      ║
    ║  nunca la vio, nunca la almacenó, nunca la transmitió.   ║
    ╚══════════════════════════════════════════════════════════╝

    Formato esperado (multipart/form-data):
        encrypted_text  : str  — Texto cifrado en Base64 (IV[12 bytes] + ciphertext)
        encrypted_file  : file — Archivo cifrado en binario (IV[12 bytes] + ciphertext)
                                 Cualquiera de los dos es opcional, pero debe haber al menos uno.
    """
    try:
        encrypted_text     = request.form.get('encrypted_text', '').strip()
        encrypted_file_obj = request.files.get('encrypted_file')

        # Necesitamos al menos texto o archivo
        if not encrypted_text and not encrypted_file_obj:
            return jsonify({'error': 'No hay datos que almacenar.'}), 400

        # Límite secundario sobre el texto (el límite global de Flask ya actúa,
        # pero esto asegura que el texto no consuma todo el espacio disponible)
        if len(encrypted_text.encode('utf-8')) > 3 * 1024 * 1024:  # 3 MB en base64
            return jsonify({'error': 'Texto demasiado grande.'}), 413

        file_bytes = None
        if encrypted_file_obj:
            file_bytes = encrypted_file_obj.read()
            if len(file_bytes) > 4 * 1024 * 1024:  # 4 MB binario
                return jsonify({'error': 'Archivo demasiado grande.'}), 413

        # ── Generar ID ────────────────────────────────────────────────────────
        # secrets.token_urlsafe(32) genera 32 bytes de entropía criptográfica
        # codificados en Base64-URL-safe → ~43 caracteres.
        # Esto equivale a 2^256 posibilidades: imposible de adivinar por fuerza bruta.
        drop_id = secrets.token_urlsafe(32)

        # ── Hash de IP para anti-spam ──────────────────────────────────────────
        ip_hash = hash_ip(get_client_ip())

        # ── Calcular expiración ───────────────────────────────────────────────
        expires_at = datetime.now(timezone.utc) + timedelta(hours=DROP_EXPIRY_HOURS)

        # ── Persistir en PostgreSQL ───────────────────────────────────────────
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO drops (id, encrypted_text, encrypted_file, ip_hash, expires_at)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        drop_id,
                        encrypted_text or None,
                        psycopg2.Binary(file_bytes) if file_bytes else None,
                        ip_hash,
                        expires_at,
                    )
                )
                conn.commit()

        return jsonify({'id': drop_id})

    except psycopg2.Error as db_err:
        app.logger.error('Error de BD en /upload: %s', db_err)
        return jsonify({'error': 'Error interno del servidor.'}), 500
    except Exception as err:
        app.logger.error('Error inesperado en /upload: %s', err)
        return jsonify({'error': 'Error interno del servidor.'}), 500


@app.route('/v/<drop_id>')
def view_drop(drop_id: str):
    """
    Muestra la página del receptor.

    Este endpoint solo consulta METADATOS no sensibles:
        - ¿Tiene texto cifrado?
        - ¿Tiene archivo cifrado?
        - ¿Cuándo expira?

    Los datos cifrados en sí NO se entregan aquí.
    El receptor debe clicar explícitamente para obtenerlos (y destruirlos).
    """
    _validate_id(drop_id)

    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute(
                """
                SELECT
                    encrypted_text IS NOT NULL AS has_text,
                    encrypted_file IS NOT NULL AS has_file,
                    expires_at
                FROM drops
                WHERE id = %s
                """,
                (drop_id,)
            )
            row = cur.fetchone()

    if not row:
        return render_template('gone.html', site_name=SITE_NAME,
                               message='Este drop no existe o ya fue reclamado.'), 410

    return render_template(
        'view.html',
        drop_id=drop_id,
        has_text=row['has_text'],
        has_file=row['has_file'],
        expires_at=row['expires_at'].isoformat(),
        site_name=SITE_NAME,
    )


@app.route('/raw/<drop_id>')
def raw_drop(drop_id: str):
    """
    Entrega los datos cifrados al receptor y destruye el drop.

    ╔══════════════════════════════════════════════════════════╗
    ║  BURN AFTER READING                                      ║
    ║                                                          ║
    ║  Una vez que este endpoint responde, el drop se elimina  ║
    ║  permanentemente de la base de datos.                    ║
    ║                                                          ║
    ║  Los datos enviados son ilegibles sin la clave AES-256   ║
    ║  que el emisor compartió con el receptor por un canal    ║
    ║  externo a este sistema. El servidor nunca tuvo esa      ║
    ║  clave y tampoco la necesita para cumplir su función.    ║
    ╚══════════════════════════════════════════════════════════╝

    Seguridad ante condiciones de carrera:
        Usamos SELECT ... FOR UPDATE para bloquear la fila durante la
        transacción, evitando que dos peticiones simultáneas al mismo
        ID obtengan los datos (y lo borren dos veces).
    """
    _validate_id(drop_id)

    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            # Bloquear la fila para evitar condición de carrera
            cur.execute(
                "SELECT id, encrypted_text, encrypted_file FROM drops WHERE id = %s FOR UPDATE",
                (drop_id,)
            )
            row = cur.fetchone()

            if not row:
                conn.commit()  # Liberar el lock antes de salir
                abort(410)     # 410 Gone: ya fue reclamado o nunca existió

            # Eliminar DENTRO de la misma transacción
            # Si algo falla antes del commit, el drop sigue existiendo (no se pierde)
            cur.execute("DELETE FROM drops WHERE id = %s", (drop_id,))
            conn.commit()

    # Construir respuesta con los datos cifrados
    payload = {
        'encrypted_text': row['encrypted_text'],  # base64 string o None
        'encrypted_file': None,
    }

    if row['encrypted_file']:
        # BYTEA → base64 para poder enviarlo en JSON sin problemas de encoding
        payload['encrypted_file'] = base64.b64encode(
            bytes(row['encrypted_file'])
        ).decode('ascii')

    return jsonify(payload)


@app.route('/decrypt-tool')
def decrypt_tool():
    """
    Herramienta de descifrado offline.
    Todo el descifrado ocurre en el navegador, sin contacto con el servidor.
    """
    return render_template('decrypt_tool.html', site_name=SITE_NAME, github_link=GITHUB_LINK)


# ─── Manejadores de error ──────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(_e):
    return render_template('gone.html', site_name=SITE_NAME,
                           message='Página no encontrada.'), 404


@app.errorhandler(410)
def gone(_e):
    return render_template('gone.html', site_name=SITE_NAME,
                           message='Este drop no existe o ya fue reclamado.'), 410


@app.errorhandler(413)
def too_large(_e):
    return jsonify({'error': 'El contenido supera el límite de 5 MB.'}), 413


# ─── Arranque directo ──────────────────────────────────────────────────────────

if __name__ == '__main__':
    debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    port  = int(os.getenv('PORT', '5001'))
    app.run(debug=debug, host='0.0.0.0', port=port)
