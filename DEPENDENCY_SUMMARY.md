# Resumen Ejecutivo de Dependencias - surisnort-ast

**Fecha:** 2025-10-29
**Python Requerido:** 3.11+ (Recomendado: 3.13+)
**Estado:** ✅ Todas las dependencias actualizadas a enero 2025

---

## TL;DR - Quick Reference

```bash
# Instalación completa
pip install -e ".[all]"

# Configurar pre-commit
pre-commit install

# Verificar
pytest && mypy src/ && ruff check .
```

---

## Decisiones Clave de Arquitectura

### 1. Parser: Lark (NO pyparsing ni textX)

**Versión:** 1.3.1+

**Razón:** Lark es superior para gramáticas complejas de reglas IDS:
- Parser Earley/LALR(1) moderno
- Maneja ambigüedades mejor que pyparsing
- Más expresivo que textX para este caso de uso
- Activamente mantenido (2024)

### 2. Validación: Pydantic v2 (NO v1)

**Versión:** 2.12.3+

**Razón:** Pydantic v2 es obligatorio para proyectos modernos:
- Core en Rust = 10-50x más rápido que v1
- Serialización JSON nativa (no necesitas dataclasses-json)
- JSON Schema generation built-in
- Soporte superior para type hints

**⚠️ ADVERTENCIA:** Pydantic v2 tiene breaking changes. Ver guía de migración.

### 3. CLI: Typer (NO click directamente)

**Versión:** 0.20.0+

**Razón:** Typer es la evolución moderna de Click:
- Type hints nativos (menos boilerplate)
- Basado en Click (misma solidez)
- Mejor DX (Developer Experience)
- Integración perfecta con Pydantic

### 4. Linting: Ruff (NO flake8/black/isort)

**Versión:** 0.14.2+

**Razón:** Ruff reemplaza 5+ herramientas:
- ❌ flake8
- ❌ black
- ❌ isort
- ❌ pyupgrade
- ❌ autoflake

**Ventajas:**
- 10-100x más rápido (escrito en Rust)
- Configuración unificada
- Auto-fix integrado
- Estándar de facto en 2025

### 5. Docs: MkDocs Material (NO Sphinx)

**Versión:** 9.6.22+

**Razón:** Mejor para proyectos nuevos:
- Markdown vs reStructuredText
- Tema moderno y responsive
- Más fácil de mantener
- Muy activamente desarrollado

---

## Resumen de Versiones Recomendadas

### Producción (Obligatorias)

| Paquete    | Versión   | Propósito            | Notas                      |
|------------|-----------|----------------------|----------------------------|
| lark       | ≥ 1.3.1   | Parser/Lexer         | Última estable 2024        |
| pydantic   | ≥ 2.12.3  | Validación           | v2 obligatorio (Dic 2024)  |
| typer      | ≥ 0.20.0  | CLI Framework        | Última estable 2024        |
| jsonschema | ≥ 4.25.1  | JSON Schema          | Draft 2020-12 (Ene 2025)   |

### Desarrollo (Recomendadas)

| Paquete         | Versión   | Reemplaza         | Notas                  |
|-----------------|-----------|-------------------|------------------------|
| pytest          | ≥ 8.4.2   | -                 | Testing framework      |
| pytest-cov      | ≥ 7.0.0   | -                 | Coverage reporting     |
| ruff            | ≥ 0.14.2  | flake8+black+isort| Linter/formatter 2025  |
| mypy            | ≥ 1.18.2  | -                 | Type checker           |
| hypothesis      | ≥ 6.142.4 | -                 | Property-based testing |
| pre-commit      | ≥ 4.3.0   | -                 | Git hooks              |
| mkdocs-material | ≥ 9.6.22  | sphinx            | Documentación moderna  |
| build           | ≥ 1.3.0   | setuptools        | PEP 517 build          |
| twine           | ≥ 6.2.0   | -                 | PyPI publishing        |

### Opcionales

| Paquete  | Versión   | Propósito              | Notas                    |
|----------|-----------|------------------------|--------------------------|
| msgpack  | ≥ 1.1.2   | Serialización binaria  | 2-10x más rápido que JSON|
| protobuf | ≥ 6.33.0  | Protocol Buffers       | ⚠️ Breaking changes v6   |

---

## Herramientas Deprecadas - NO USAR

| ❌ NO USAR     | ✅ USAR EN SU LUGAR | Razón                            |
|----------------|---------------------|----------------------------------|
| flake8         | ruff                | 10-100x más lento                |
| black          | ruff format         | Herramienta separada innecesaria |
| isort          | ruff                | Integrado en ruff                |
| pyupgrade      | ruff                | Integrado en ruff (UP rules)     |
| autoflake      | ruff                | Integrado en ruff                |
| pydantic v1    | pydantic v2         | v1 en modo mantenimiento         |
| dataclasses-json| pydantic v2        | Redundante con pydantic v2       |
| setuptools (deps)| build             | Solo build-time, no runtime      |

---

## Matriz de Compatibilidad

### Python

| Versión | Status | Notas                          |
|---------|--------|--------------------------------|
| 3.14    | ✅      | Totalmente soportado           |
| 3.13    | ✅      | Recomendado                    |
| 3.12    | ✅      | Totalmente soportado           |
| 3.11    | ✅      | Mínimo requerido               |
| 3.10    | ❌      | No soportado (EOL Octubre 2026)|
| 3.9     | ❌      | No soportado (EOL Octubre 2025)|

### Dependencias Críticas

Todas las dependencias están verificadas para Python 3.13+:

- ✅ lark 1.3.1 - Python 3.8+
- ✅ pydantic 2.12.3 - Python 3.8+
- ✅ typer 0.20.0 - Python 3.7+
- ✅ pytest 8.4.2 - Python 3.8+
- ✅ ruff 0.14.2 - Python 3.7+
- ✅ mypy 1.18.2 - Python 3.8+

---

## Advertencias y Consideraciones

### ⚠️ Pydantic v2 - Breaking Changes

Si migras de Pydantic v1 a v2:

**Cambios principales:**
```python
# v1 (DEPRECATED)
model = Model.parse_obj(data)
dict_data = model.dict()

# v2 (CURRENT)
model = Model.model_validate(data)
dict_data = model.model_dump()
```

**Recursos:**
- [Guía de Migración Oficial](https://docs.pydantic.dev/latest/migration/)
- [Codemods Automatizados](https://github.com/pydantic/bump-pydantic)

### ⚠️ Protobuf 6.x - Breaking Changes

Si usas protobuf (opcional):

- Requiere sintaxis proto3
- Cambios en comportamiento de campos
- Verificar compatibilidad con .proto existentes

**Alternativa:** Usar msgpack (más simple, sin breaking changes)

### ⚠️ Ruff - Rápida Evolución

Ruff está en desarrollo activo:

- Releases frecuentes (1-2 semanas)
- Nuevas reglas añadidas regularmente
- Usar `~=0.14.2` para bloquear versión minor

**Recomendación:** Actualizar mensualmente y revisar changelog

### ⚠️ Pre-commit - Python 3.9 Mínimo

Pre-commit requiere Python 3.9+ (no 3.8):

- Si tu proyecto soporta Python 3.8, no uses pre-commit en CI
- O usa Python 3.9+ solo para pre-commit hooks

---

## Estrategia de Actualización

### Frecuencia Recomendada

| Tipo           | Frecuencia | Herramienta          |
|----------------|------------|----------------------|
| Parches        | Semanal    | `pip install --upgrade` |
| Minor updates  | Mensual    | Revisión manual      |
| Major updates  | Trimestral | Análisis de breaking changes |
| Seguridad      | Inmediato  | Dependabot/Renovate  |

### Herramientas de Automatización

```bash
# Ver dependencias desactualizadas
pip list --outdated

# Auditoría de seguridad
pip install pip-audit
pip-audit

# Árbol de dependencias
pip install pipdeptree
pipdeptree
```

### CI/CD Recommendations

```yaml
# .github/workflows/dependencies.yml
name: Dependency Updates
on:
  schedule:
    - cron: '0 0 * * 1'  # Lunes a medianoche
  workflow_dispatch:

jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.13'
      - run: pip install pip-audit
      - run: pip-audit
      - run: pip list --outdated
```

---

## Checklist de Instalación

### Setup Inicial

- [ ] Python 3.11+ instalado (`python --version`)
- [ ] Entorno virtual creado (`python -m venv venv`)
- [ ] Venv activado (`source venv/bin/activate`)
- [ ] pip actualizado (`python -m pip install --upgrade pip`)

### Instalación de Dependencias

- [ ] Dependencias instaladas (`pip install -e ".[all]"`)
- [ ] Pre-commit hooks instalados (`pre-commit install`)
- [ ] Versiones verificadas (`pip list`)

### Verificación

- [ ] Tests pasan (`pytest`)
- [ ] Type checking sin errores (`mypy src/`)
- [ ] Linting sin errores (`ruff check .`)
- [ ] Pre-commit funciona (`pre-commit run --all-files`)

### Configuración IDE

- [ ] Intérprete configurado (venv)
- [ ] Ruff habilitado
- [ ] MyPy habilitado
- [ ] Format on save activado

---

## Contacto y Soporte

**Dudas sobre dependencias:**
- Ver documentación detallada: [DEPENDENCIES.md](DEPENDENCIES.md)
- Ver instalación paso a paso: [INSTALL.md](INSTALL.md)
- Reportar problemas: [GitHub Issues](https://github.com/yourusername/surisnort-ast/issues)

**Autor:** Marc Rivero López
**Licencia:** GNU General Public License v3 (GPLv3)
**Fecha:** 2025-10-29

---

## Archivos de Configuración Generados

1. **[pyproject.toml](pyproject.toml)** - Configuración completa del proyecto
2. **[.pre-commit-config.yaml](.pre-commit-config.yaml)** - Hooks de pre-commit
3. **[DEPENDENCIES.md](DEPENDENCIES.md)** - Análisis detallado de dependencias
4. **[INSTALL.md](INSTALL.md)** - Guía de instalación paso a paso
5. **[requirements-example.txt](requirements-example.txt)** - Ejemplo de requirements congelados

---

**✅ Proyecto configurado con las mejores prácticas de Python 2025**
