#!/bin/bash

# Definir la ruta base del proyecto
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

# Configurar entorno virtual si no existe
if [ ! -d "${BASE_DIR}/venv" ]; then
    echo "[+] Creando entorno virtual..."
    python3 -m venv "${BASE_DIR}/venv"
    source "${BASE_DIR}/venv/bin/activate"
    pip install -r "${BASE_DIR}/requirements.txt"
else
    source "${BASE_DIR}/venv/bin/activate"
fi

# Asegurar que todos los directorios necesarios existen
mkdir -p "${BASE_DIR}/logs"

# Exportar variables de entorno necesarias
export FLASK_APP="${BASE_DIR}/modules/dashboard/app.py"
export FLASK_ENV=production
export PYTHONPATH="${BASE_DIR}"

# Iniciar el dashboard
echo "[+] Iniciando dashboard..."
python -m flask run --host=0.0.0.0 --port=5000