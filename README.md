# Secret Sentinel

**Detector de posibles credenciales expuestas en archivos y proyectos.**

Secret Sentinel es una herramienta de seguridad informática desarrollada en Python. Su objetivo es ayudar a identificar posibles credenciales almacenadas directamente en el código fuente o en archivos de un proyecto antes de compartirlos o publicarlos.

Busca patrones asociados a claves API, contraseñas, tokens de acceso y claves privadas. Cuando encuentra una coincidencia, informa del archivo, la línea, el tipo de hallazgo y su nivel de gravedad orientativo, sin mostrar el valor detectado.

## Características

- Escaneo recursivo de archivos y directorios.
- Detección de credenciales genéricas.
- Reconocimiento de patrones de AWS, GitHub, Stripe y Slack.
- Detección de contraseñas con nombres como DB_PASSWORD y MYSQL_PASSWORD.
- Identificación de marcadores de claves privadas.
- Detección de archivos y líneas donde aparecen posibles credenciales.
- Clasificación orientativa de gravedad.
- Exclusión de directorios como `.venv`, `.git` y `__pycache__`.
- Omisión de archivos binarios y enlaces simbólicos.
- Resultados sin revelar los valores detectados.
- Códigos de salida para facilitar su integración con otros programas.

## Tecnologías

- Python 3.10 o superior.
- Expresiones regulares (`re`).
- `pathlib` y `os` para gestionar y recorrer archivos.
- `argparse` para recibir argumentos desde la terminal.
- `unittest` para las pruebas automáticas.

Utiliza exclusivamente bibliotecas de la biblioteca estándar de Python. No requiere dependencias externas.

## Requisitos

- Python 3.10 o superior.
- Linux, Windows o macOS con Python instalado.

## Instalación

Clona el repositorio y entra en su directorio:

```bash
git clone https://github.com/eduar-q/secret-sentinel.git
````

Crea un entorno virtual:

```
python3 -m venv .venv
```

Actívalo en Linux o macOS:

```
source .venv/bin/activate
```

En Windows, desde PowerShell:

```
.\.venv\Scripts\Activate.ps1
```

No es necesario instalar paquetes adicionales.

## **Uso**

Para analizar la carpeta actual:

```
python -m secret_sentinel
```

Para analizar una carpeta específica:

```
python -m secret_sentinel ruta/de/la/carpeta
```

Ejemplo:

```
python -m secret_sentinel tests/samples
```

### **Ejemplo de resultados**

```
POSIBLES CREDENCIALES DETECTADAS

ARCHIVO                             LINEA    TIPO             GRAVEDAD
---------------------------------------------------------------------------
fake_secrets.py                     4        API Key          HIGH
fake_secrets.py                     6        Password         HIGH
fake_secrets.py                     8        Access Token     HIGH
fake_secrets.py                     11       Private Key      CRITICAL

Total de coincidencias: 4
```

Los valores detectados no se incluyen en el informe.

## **Códigos de salida**

| Código | Significado                                     |
| ------ | ----------------------------------------------- |
| 0      | El análisis terminó sin coincidencias.          |
| 1      | Se encontraron posibles credenciales.           |
| 2      | Se produjo un error con el directorio indicado. |

Estos códigos permiten que otros programas puedan interpretar el resultado del análisis.

## **Pruebas**

El proyecto utiliza `unittest`, incluido en Python.

Para ejecutar todas las pruebas:

```
python -m unittest discover -s tests -v
```

Las pruebas automáticas comprueban:

- Detección de credenciales genéricas con y sin comillas.
- Reconocimiento de credenciales de AWS, GitHub, Stripe y Slack.
- Detección de contraseñas con prefijos habituales.
- Reconocimiento de distintos encabezados de claves privadas.
- Exclusión de variables de entorno y referencias dinámicas.
- Ausencia de alertas ante valores públicos y texto normal.
- Protección de los valores detectados.
- Recorrido de subdirectorios y exclusión de carpetas configuradas.
- Comportamiento con archivos binarios y enlaces simbólicos.
- Detección de credenciales en archivos completos.
- Funcionamiento de los códigos de salida de la terminal.

**Estado de desarrollo:** 26 pruebas automáticas superadas.

**Estado de desarrollo:** 9 pruebas automáticas superadas.

## **Estructura del proyecto**

```
secret-sentinel/
│
├── secret_sentinel/
│   ├── init.py
│   ├── main.py
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

## **Limitaciones**

Secret Sentinel es una herramienta de detección basada en patrones. No realiza una auditoría completa de seguridad.

- Puede generar falsos positivos.
- Puede pasar por alto credenciales que no coincidan con sus reglas.
- No verifica si una credencial detectada es válida o está activa.
- No determina si una credencial ya fue comprometida.
- No garantiza que un proyecto esté libre de secretos.

Los niveles de gravedad son orientativos y no representan una evaluación formal del riesgo.

La ausencia de alertas no garantiza que un proyecto sea seguro.

## **Objetivo del proyecto**

Desarrollar una herramienta ligera y accesible que permita revisar archivos y proyectos en busca de posibles credenciales expuestas antes de compartirlos.

Es un proyecto de aprendizaje y aplicación práctica de Python y seguridad defensiva.
