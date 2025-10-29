# Guía de Instalación - surisnort-ast

**Versiones recomendadas actualizadas para 2025**

Esta guía proporciona instrucciones detalladas para instalar surisnort-ast con las versiones más actuales y seguras de todas las dependencias.

## Requisitos del Sistema

### Python

- **Mínimo:** Python 3.11
- **Recomendado:** Python 3.13 o 3.14
- **Tu sistema:** Python 3.14.0 ✅

### Sistema Operativo

- ✅ macOS (verificado)
- ✅ Linux (Ubuntu 20.04+, Debian 11+, Fedora 35+)
- ✅ Windows 10/11 con WSL2 o nativo

## Instalación Paso a Paso

### 1. Preparar Entorno Virtual

```bash
# Navegar al directorio del proyecto
cd /Users/seifreed/tools/malware/surinort-ast

# Eliminar venv anterior si existe
rm -rf venv

# Crear nuevo entorno virtual con Python 3.13+
python3.14 -m venv venv

# Activar entorno virtual
source venv/bin/activate  # macOS/Linux
# venv\Scripts\activate   # Windows
```

### 2. Actualizar pip

```bash
# Actualizar pip a la última versión
python -m pip install --upgrade pip

# Verificar versión de pip
pip --version  # Debería mostrar pip 25.2+
```

### 3. Instalar Dependencias de Producción

```bash
# Instalación básica (solo producción)
pip install -e .

# O con todas las dependencias
pip install -e ".[all]"
```

Esto instalará:
- lark 1.3.1+
- pydantic 2.12.3+
- typer 0.20.0+
- jsonschema 4.25.1+

### 4. Instalar Dependencias de Desarrollo

```bash
# Instalar todas las dependencias de desarrollo
pip install -e ".[dev]"
```

Esto instalará:
- pytest 8.4.2+
- pytest-cov 7.0.0+
- ruff 0.14.2+
- mypy 1.18.2+
- hypothesis 6.142.4+
- pre-commit 4.3.0+
- mkdocs-material 9.6.22+
- build 1.3.0+
- twine 6.2.0+

### 5. Configurar Pre-commit Hooks

```bash
# Instalar los hooks en el repositorio git
pre-commit install

# Verificar instalación
pre-commit --version

# (Opcional) Ejecutar pre-commit en todos los archivos
pre-commit run --all-files
```

### 6. Verificar Instalación

```bash
# Verificar que las herramientas están instaladas
python --version
pytest --version
ruff --version
mypy --version
pre-commit --version

# Ejecutar tests
pytest

# Verificar type checking
mypy src/

# Verificar linting
ruff check .
```

## Instalaciones Alternativas

### Solo Dependencias Opcionales de Serialización

```bash
pip install -e ".[serialization]"
```

Esto instalará:
- msgpack 1.1.2+
- protobuf 6.33.0+

### Desde PyPI (cuando esté publicado)

```bash
# Instalación básica
pip install surisnort-ast

# Con todas las opciones
pip install "surisnort-ast[all]"
```

## Verificación de Versiones Instaladas

```bash
# Listar todas las dependencias instaladas
pip list

# Verificar versiones específicas
pip show lark pydantic typer pytest ruff mypy
```

### Versiones Esperadas (Enero 2025)

```
lark         >= 1.3.1
pydantic     >= 2.12.3
typer        >= 0.20.0
jsonschema   >= 4.25.1
pytest       >= 8.4.2
pytest-cov   >= 7.0.0
ruff         >= 0.14.2
mypy         >= 1.18.2
hypothesis   >= 6.142.4
pre-commit   >= 4.3.0
mkdocs-material >= 9.6.22
build        >= 1.3.0
twine        >= 6.2.0
msgpack      >= 1.1.2
protobuf     >= 6.33.0
```

## Solución de Problemas

### Error: "No module named 'pydantic'"

```bash
# Verificar que el venv está activado
which python  # Debería mostrar la ruta al venv

# Reinstalar pydantic
pip install --force-reinstall pydantic>=2.12.3
```

### Error: "pre-commit: command not found"

```bash
# Verificar que pre-commit está instalado
pip show pre-commit

# Reinstalar si es necesario
pip install pre-commit>=4.3.0

# Reinstalar hooks
pre-commit install
```

### Error: "ImportError: cannot import name 'BaseModel' from 'pydantic'"

Este error indica que se instaló Pydantic v1 en lugar de v2:

```bash
# Desinstalar y reinstalar Pydantic v2
pip uninstall pydantic
pip install "pydantic>=2.12.3"
```

### Advertencias de protobuf 6.x

Si usas protobuf y ves advertencias sobre compatibilidad:

```bash
# Protobuf 6.x requiere proto3 syntax
# Verifica tus archivos .proto y actualiza si es necesario
```

### Conflictos de Dependencias

```bash
# Ver árbol de dependencias
pip install pipdeptree
pipdeptree

# Resolver conflictos
pip install --force-reinstall -e ".[all]"
```

## Actualización de Dependencias

### Actualizar a las Últimas Versiones

```bash
# Actualizar pip primero
python -m pip install --upgrade pip

# Actualizar todas las dependencias
pip install --upgrade -e ".[all]"

# Actualizar pre-commit hooks
pre-commit autoupdate
```

### Verificar Seguridad

```bash
# Instalar herramientas de auditoría
pip install pip-audit

# Auditar dependencias
pip-audit
```

## Configuración del IDE

### Visual Studio Code

Crear `.vscode/settings.json`:

```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/venv/bin/python",
  "python.linting.enabled": false,
  "python.formatting.provider": "none",
  "[python]": {
    "editor.defaultFormatter": "charliermarsh.ruff",
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
      "source.fixAll": true,
      "source.organizeImports": true
    }
  },
  "ruff.enable": true,
  "ruff.lint.enable": true,
  "ruff.format.enable": true,
  "mypy-type-checker.args": ["--strict"],
  "python.testing.pytestEnabled": true,
  "python.testing.unittestEnabled": false
}
```

Extensiones recomendadas:
- `charliermarsh.ruff` - Ruff (linting y formatting)
- `ms-python.python` - Python
- `ms-python.vscode-pylance` - Pylance
- `ms-python.mypy-type-checker` - MyPy

### PyCharm

1. Configurar intérprete: Settings → Project → Python Interpreter → Seleccionar `venv/bin/python`
2. Habilitar Ruff: Settings → Tools → External Tools → Agregar Ruff
3. Configurar MyPy: Settings → Tools → External Tools → Agregar MyPy

## Build y Publicación (para mantenedores)

### Build Local

```bash
# Limpiar builds anteriores
rm -rf dist/ build/ *.egg-info

# Build del paquete
python -m build

# Verificar el paquete
twine check dist/*
```

### Publicar a Test PyPI

```bash
# Configurar credenciales en ~/.pypirc
twine upload --repository testpypi dist/*

# Probar instalación desde Test PyPI
pip install --index-url https://test.pypi.org/simple/ surisnort-ast
```

### Publicar a PyPI

```bash
# Publicar a PyPI producción
twine upload dist/*
```

## Recursos Adicionales

- [pyproject.toml](/Users/seifreed/tools/malware/surinort-ast/pyproject.toml) - Configuración completa del proyecto
- [DEPENDENCIES.md](/Users/seifreed/tools/malware/surinort-ast/DEPENDENCIES.md) - Análisis detallado de dependencias
- [.pre-commit-config.yaml](/Users/seifreed/tools/malware/surinort-ast/.pre-commit-config.yaml) - Configuración de pre-commit

## Siguiente Paso

Después de instalar, consulta:
- [README.md](README.md) - Uso básico
- [ARCHITECTURE.md](ARCHITECTURE.md) - Arquitectura del proyecto
- [CONTRIBUTING.md](CONTRIBUTING.md) - Guía para contribuir

---

**Nota:** Este proyecto usa herramientas modernas de Python optimizadas con Rust (Ruff, Pydantic v2) para máximo rendimiento y mejor experiencia de desarrollo.
