#!/bin/bash

# Colores para mensajes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Definir la ruta base del proyecto
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Error: Python3 no está instalado${NC}"
    exit 1
fi

# Configurar entorno virtual si no existe
if [ ! -d "${BASE_DIR}/venv" ]; then
    echo -e "${YELLOW}[+] Creando entorno virtual...${NC}"
    python3 -m venv "${BASE_DIR}/venv"
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Error creando el entorno virtual${NC}"
        exit 1
    fi
    source "${BASE_DIR}/venv/bin/activate"
    echo -e "${YELLOW}[+] Instalando dependencias...${NC}"
    pip install -r "${BASE_DIR}/requirements.txt"
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Error instalando dependencias${NC}"
        exit 1
    fi
else
    source "${BASE_DIR}/venv/bin/activate"
fi

# Asegurar que todos los directorios necesarios existen
mkdir -p "${BASE_DIR}/logs"
mkdir -p "${BASE_DIR}/modules/dashboard/static/js"
mkdir -p "${BASE_DIR}/modules/dashboard/static/css"

# Verificar si hay un proceso ya corriendo en el puerto 5000
if netstat -tuln | grep -q ":5000 "; then
    echo -e "${RED}[!] El puerto 5000 ya está en uso${NC}"
    exit 1
fi

# Exportar variables de entorno necesarias
export FLASK_APP="${BASE_DIR}/modules/dashboard/app.py"
export FLASK_ENV=production
export PYTHONPATH="${BASE_DIR}"

# Iniciar el dashboard
echo -e "${GREEN}[+] Iniciando dashboard en http://localhost:5000${NC}"
python -m flask run --host=0.0.0.0 --port=5000