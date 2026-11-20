# Ejemplo de configuración pública para una aplicación.
# Estos valores describen el comportamiento del programa,
# no contienen credenciales ni información de acceso.

APP_NAME = "Secret Sentinel"
DEBUG_MODE = False
MAX_FILE_SIZE = 1048576


def get_app_info():
    """Devuelve información básica sobre la configuración."""
    return {
        "name": APP_NAME,
        "debug": DEBUG_MODE,
        "max_file_size": MAX_FILE_SIZE
    }
