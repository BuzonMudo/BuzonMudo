"""
Script de Limpieza de Drops Expirados

Este script elimina los drops que superaron su fecha de expiración
sin haber sido reclamados.

Configuración recomendada en cron (cada hora):
    0 * * * * /ruta/al/venv/bin/python /ruta/al/proyecto/cleanup.py >> /var/log/deaddrop_cleanup.log 2>&1

O con crontab -e:
    0 * * * * cd /ruta/al/proyecto && python cleanup.py

Uso manual:
    python cleanup.py
"""

import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()


def cleanup():
    """Elimina todos los drops cuya expires_at ya pasó."""
    try:
        conn = psycopg2.connect(
            dbname=os.getenv('DB_NAME',     'buzonmudo'),
            user=os.getenv('DB_USER',       'postgres'),
            password=os.getenv('DB_PASSWORD', ''),
            host=os.getenv('DB_HOST',       'localhost'),
            port=os.getenv('DB_PORT',       '5432'),
        )

        with conn:
            with conn.cursor() as cur:
                # RETURNING id nos permite saber cuántos y cuáles se borraron
                cur.execute(
                    "DELETE FROM drops WHERE expires_at < NOW() RETURNING id"
                )
                deleted = cur.fetchall()

        conn.close()

        count = len(deleted)
        if count > 0:
            print(f'[cleanup] {count} drop(s) expirado(s) eliminado(s).')
        else:
            print('[cleanup] Sin drops expirados.')

    except psycopg2.Error as e:
        print(f'[cleanup] Error de BD: {e}')
        raise


if __name__ == '__main__':
    cleanup()
