# Buzón Mudo
**Plataforma efímera de intercambio de archivos de Conocimiento Cero (Zero-Knowledge).**

Buzón Mudo es un servicio web diseñado para el intercambio hiper-seguro de texto y archivos. La premisa es simple: **El servidor es ciego.** No podemos leer tus mensajes, no podemos ver tus archivos y no tenemos las llaves criptográficas. Todo se cifra en tu dispositivo antes de tocar la red y se destruye irreversiblemente tras su primera lectura.

## Arquitectura de Seguridad (Client-Side Encryption)

Este proyecto no depende de "promesas" de privacidad, sino de matemáticas comprobables.

1. **Cifrado Local:** Al seleccionar un archivo, tu navegador genera una clave `AES-256-GCM`.
2. **El Servidor Ciego:** El navegador cifra los datos localmente y envía un bloque de datos ininteligibles (Ciphertext) al servidor. **La clave nunca se envía al backend.**
3. **Tierra Arrasada:** Una vez que el receptor usa el enlace y el servidor entrega el paquete cifrado, la base de datos elimina el registro instantáneamente. Si nadie lo reclama, un *cron job* lo purga en 72 horas.

## Stack Tecnológico

* **Frontend:** Vanilla JavaScript (Web Crypto API para rendimiento criptográfico nativo), HTML5, Bootstrap 5.
* **Backend:** Python 3 (Flask). Actúa únicamente como un pasamanos de paquetes binarios cifrados.
* **Base de Datos:** PostgreSQL. Almacena temporalmente los blobs binarios y expira registros.

## Despliegue en Servidor Propio (Self-Hosted)

Si quieres levantar tu propio nodo:

1. **Clonar y preparar entorno:**
   ```bash
   git clone [https://github.com/BuzonMudo/BuzonMudo](https://github.com/BuzonMudo/BuzonMudo)
   cd buzonmudo
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Crear la base de datos en PostgreSQL:**
   ```bash
   sudo -u postgres psql -c "CREATE DATABASE buzonmudo;"
   ```
3. **Insertar las tablas:**
   ```bash
   sudo -u postgres psql -d buzonmudo < schema.sql
   ```
4. **Crea el .env en la raíz:**
   ```bash
   # Variables de Entorno DB
   DB_NAME=buzonmudo
   DB_USER=postgres
   DB_PASSWORD=tu_contraseña
   DB_HOST=localhost
   DB_PORT=5432

   # Aplicación
   SITE_NAME="Buzón Mudo"
   GITHUB_LINK=[https://github.com/tu-usuario/tu-repo](https://github.com/tu-usuario/tu-repo)
   DROP_EXPIRY_HOURS=72
   PORT=5000
   FLASK_DEBUG=false

   # Donaciones
   CRYPTO_RECEIVE=XMR,BTC
   XMR_ADDRESS=tu_direccion_monero_aqui
   BTC_ADDRESS=tu_direccion_bitcoin_aqui
   ```
5. **Configura un Cron para ejecutar cleanup.py cada hora y purgar drops expirados:**
   ```bash
   0 * * * * /ruta/al/proyecto/venv/bin/python /ruta/al/proyecto/cleanup.py
   ```
6. **Ejecutar:**
   ```bash
   python app.py
   ```
   
Nota: python app.py es ideal para pruebas locales. Para entornos de producción, se recomienda Gunicorn detrás de Nginx.
