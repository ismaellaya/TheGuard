#!/bin/bash

# Configurar entorno virtual si no existe
if [ ! -d "venv" ]; then
    echo "[+] Creando entorno virtual..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

# Asegurar que todos los directorios necesarios existen
mkdir -p logs

# Exportar variables de entorno necesarias
export FLASK_APP=modules/dashboard/app.py
export FLASK_ENV=production

# Iniciar el dashboard
echo "[+] Iniciando dashboard..."
python -m flask run --host=0.0.0.0 --port=5000