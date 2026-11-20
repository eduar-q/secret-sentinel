# Secret Sentinel

**Detector de posibles credenciales expuestas en archivos y proyectos.**

Secret Sentinel es una herramienta de seguridad informática desarrollada en Python. Su objetivo es ayudar a identificar posibles credenciales almacenadas directamente en el código fuente o en archivos de un proyecto antes de compartirlos o publicarlos.

Busca patrones asociados a claves API, contraseñas, tokens de acceso y claves privadas. Cuando encuentra una coincidencia, informa del archivo, la línea, el tipo de hallazgo y su nivel de gravedad orientativo, sin mostrar el valor detectado.

## Características

- Escaneo recursivo de archivos y directorios.
- Detección de patrones habituales de credenciales.
- Identificación del archivo y número de línea.
- Clasificación orientativa de la gravedad.
- Exclusión de directorios como `.venv`, `.git` y `__pycache__`.
- Resultados sin revelar el contenido de las posibles credenciales.
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

Las pruebas actuales comprueban:

- Reconocimiento de los patrones definidos.
- Ausencia de alertas ante texto normal.
- Protección de los valores detectados en los resultados.
- Identificación de credenciales dentro de archivos.
- Exclusión de directorios configurados.
- Comportamiento con archivos sin coincidencias.
- Detección de credenciales con y sin comillas.
- Exclusión de accesos a variables de entorno mediante `os.getenv()` y `os.environ[]` para evitar falsos positivos.

**Estado de desarrollo:** 9 pruebas automáticas superadas.

## **Estructura del proyecto**

```
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
│   ├── test_detector.py
│   ├── test_scanner.py
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
