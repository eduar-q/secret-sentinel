# Secret Sentinel

**Herramienta desarrollada en Python para detectar posibles credenciales expuestas en archivos y proyectos.**

Cuando trabajamos en un proyecto podemos dejar accidentalmente contraseñas, claves de acceso o tokens dentro de algún archivo. Si después compartimos ese proyecto en internet, esa información podría quedar expuesta.

Secret Sentinel busca ayudar a prevenir estos descuidos. Analiza los archivos de una carpeta e identifica patrones que podrían corresponder a credenciales, indicando dónde se encuentran sin mostrar su contenido.

## Características

- Escaneo recursivo de archivos y directorios.
- Detección de contraseñas, claves API y tokens de acceso.
- Reconocimiento de patrones de credenciales de AWS, GitHub, Stripe y Slack.
- Detección de contraseñas con nombres como `DB_PASSWORD`, `DATABASE_PASSWORD` y `MYSQL_PASSWORD`.
- Identificación de distintos marcadores de claves privadas.
- Información sobre el archivo, la línea y el tipo de posible credencial.
- Clasificación orientativa de la gravedad.
- Exclusión de directorios como `.git`, `.venv`, `__pycache__`, `node_modules`, `build` y `dist`.
- Omisión de archivos binarios y enlaces simbólicos durante el análisis.
- Resultados que no muestran los valores detectados.
- Códigos de salida para facilitar su uso desde otros programas.

## Tecnologías

- Python 3.10 o superior.
- Expresiones regulares (`re`) para reconocer patrones.
- `pathlib` y `os` para gestionar y recorrer archivos.
- `argparse` para recibir argumentos desde la terminal.
- `unittest` para ejecutar las pruebas automáticas.

Secret Sentinel utiliza exclusivamente bibliotecas incluidas en Python. No necesita instalar dependencias externas.

## Requisitos

- Python 3.10 o superior.
- Linux, Windows o macOS.
- Git para clonar el repositorio.

## Instalación

Clona el repositorio:

```bash
git clone https://github.com/eduar-q/secret-sentinel.git
```

Entra en la carpeta del proyecto:

```bash
cd secret-sentinel
```

### Linux y macOS

Crea un entorno virtual:

```bash
python3 -m venv .venv
```

Actívalo:

```bash
source .venv/bin/activate
```

### Windows (PowerShell)

Crea el entorno virtual:

```powershell
py -3 -m venv .venv
```

Actívalo:

```powershell
.\.venv\Scripts\Activate.ps1
```

No es necesario instalar paquetes adicionales.

## Uso

Para analizar la carpeta actual:

```bash
python -m secret_sentinel
```

Para analizar una carpeta específica:

```bash
python -m secret_sentinel ruta/de/la/carpeta
```

Por ejemplo:

```bash
python -m secret_sentinel tests/samples
```

Secret Sentinel recorrerá la carpeta indicada y sus subdirectorios, respetando las exclusiones configuradas.

### Ejemplo de resultados

```text
POSIBLES CREDENCIALES DETECTADAS

ARCHIVO                             LINEA    TIPO             GRAVEDAD
---------------------------------------------------------------------------
fake_secrets.py                     4        API Key          HIGH
fake_secrets.py                     6        Password         HIGH
fake_secrets.py                     8        Access Token     HIGH
fake_secrets.py                     11       Private Key      CRITICAL

Total de coincidencias: 4
```

Los valores detectados no aparecen en el informe. Solamente se muestra la información necesaria para localizar y revisar cada posible exposición.

## Códigos de salida

| Código | Significado |
|:---:|---|
| `0` | El análisis terminó sin encontrar coincidencias. |
| `1` | Se encontraron posibles credenciales. |
| `2` | Se produjo un error con el directorio indicado. |

Estos códigos permiten que otros programas puedan interpretar el resultado del análisis.

## Pruebas automáticas

El proyecto utiliza `unittest`, incluido en Python.

Para ejecutar todas las pruebas:

```bash
python -m unittest discover -s tests -v
```

Las **26 pruebas automáticas** comprueban:

- Detección de credenciales genéricas con y sin comillas.
- Reconocimiento de patrones de AWS, GitHub, Stripe y Slack.
- Detección de contraseñas con prefijos habituales.
- Reconocimiento de distintos encabezados de claves privadas.
- Exclusión de referencias a variables de entorno.
- Ausencia de alertas ante texto normal, valores públicos y referencias dinámicas.
- Protección de los valores detectados en los resultados.
- Recorrido de subdirectorios y exclusión de carpetas configuradas.
- Comportamiento ante archivos binarios y enlaces simbólicos.
- Detección de credenciales en archivos completos.
- Funcionamiento de los códigos de salida de la terminal.

**Estado de desarrollo: 26 pruebas automáticas superadas.**

## Estructura del proyecto

```text
secret-sentinel/
│
├── secret_sentinel/
│   ├── __init__.py
│   ├── __main__.py
│   ├── scanner.py
│   ├── detector.py
│   └── rules.py
│
├── tests/
│   ├── test_cli.py
│   ├── test_detector.py
│   ├── test_scanner.py
│   │
│   └── samples/
│       ├── safe_file.py
│       └── fake_secrets.py
│
├── .gitignore
├── README.md
├── LICENSE
└── requirements.txt
```

## Limitaciones

Secret Sentinel es una herramienta de detección basada en patrones. No realiza una auditoría completa de seguridad.

- Puede generar falsos positivos.
- Puede pasar por alto credenciales cuyos formatos no reconozca.
- No verifica si una credencial detectada es válida o está activa.
- No determina si una credencial ya fue comprometida.
- No revisa el historial de Git ni recupera información que ya haya sido publicada.
- La detección de claves privadas se basa en sus encabezados; no valida su contenido criptográfico.
- No garantiza que un proyecto esté libre de secretos.

Los niveles de gravedad son orientativos y no representan una evaluación formal del riesgo.

La ausencia de alertas no garantiza que un proyecto sea seguro.

## Objetivo del proyecto

Desarrollar una herramienta ligera y accesible que permita revisar archivos y proyectos en busca de posibles credenciales expuestas antes de compartirlos o publicarlos.

Es un proyecto personal de aprendizaje y aplicación práctica de Python y seguridad defensiva.
