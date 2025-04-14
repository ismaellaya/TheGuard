# TheGuard

Sistema de detección y prevención de intrusiones (IDS/IPS) modular que combina múltiples técnicas de análisis para la detección de amenazas en tiempo real.

## Módulos Principales

1. **IDS basado en firmas** (modules/ids_firmas)
   - Detección mediante Snort
   - Reglas personalizadas para ataques comunes

2. **Análisis de Anomalías** (modules/analisis_anomalias)
   - Modelos de Machine Learning (Autoencoder + LSTM)
   - Detección de comportamientos anómalos

3. **Deep Packet Inspection** (modules/dpi)
   - Análisis profundo de paquetes
   - Detección de patrones maliciosos

4. **Monitorización IP** (modules/monitorizacion_ip)
   - Seguimiento de conexiones
   - Integración con AbuseIPDB

5. **Dashboard** (modules/dashboard)
   - Panel de control web
   - Visualización de alertas y estadísticas

## Instalación

1. Clonar el repositorio:
   ```bash
   git clone https://github.com/usuario/TheGuard.git
   cd TheGuard
   ```

2. Crear un entorno virtual e instalar dependencias:
   ```bash
   python -m venv venv
   source venv/bin/activate  # En Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Configurar Snort:
   ```bash
   cd modules/ids_firmas
   ./snort_setup.sh
   ```

4. Configurar las variables de entorno en config/global_config.yaml

## Uso

1. Iniciar todos los servicios:
   ```bash
   ./scripts/run_project.sh
   ```

2. Acceder al dashboard:
   http://localhost:5000

## Estructura del Proyecto

```
TheGuard/
├── config/          # Configuración global y por módulo
├── docs/           # Documentación detallada
├── modules/        # Módulos principales
├── scripts/        # Scripts de utilidad
└── tests/          # Tests unitarios y de integración
```

## Documentación

Consultar la carpeta `docs/` para documentación detallada sobre:
- Introducción y objetivos
- Especificaciones técnicas
- Diseño y arquitectura

## Licencia

Este proyecto está bajo la licencia MIT.
