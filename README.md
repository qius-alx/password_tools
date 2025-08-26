# 🔐 Password Security Tool

<div align="center">

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Security](https://img.shields.io/badge/Security-AES--256-red.svg)
![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)

**Herramienta completa de ciberseguridad para análisis, generación y gestión segura de contraseñas**

[🚀 Instalación](#-instalación) • [📖 Uso](#-uso) • [🔧 Características](#-características) • [🛡️ Seguridad](#️-seguridad)

</div>

---

## 📋 Tabla de Contenidos

- [🔐 Password Security Tool](#-password-security-tool)
  - [📋 Tabla de Contenidos](#-tabla-de-contenidos)
  - [🎯 Descripción](#-descripción)
  - [✨ Características Principales](#-características-principales)
  - [🚀 Instalación](#-instalación)
    - [Requisitos](#requisitos)
    - [Instalación Rápida](#instalación-rápida)
  - [📖 Uso](#-uso)
    - [Ejecutar la Herramienta](#ejecutar-la-herramienta)
    - [Opciones Disponibles](#opciones-disponibles)
  - [🔧 Funcionalidades Detalladas](#-funcionalidades-detalladas)
    - [1. 🔍 Análisis de Contraseñas](#1--análisis-de-contraseñas)
    - [2. 🎲 Generador de Contraseñas](#2--generador-de-contraseñas)
    - [3. 🔐 Gestor de Contraseñas](#3--gestor-de-contraseñas)
    - [4. 🌐 Verificación HIBP](#4--verificación-hibp)
    - [5. 📝 Convertidor de Frases](#5--convertidor-de-frases)
  - [🛡️ Seguridad](#️-seguridad)
  - [📦 Dependencias](#-dependencias)
  - [🔗 API Externa](#-api-externa)
  - [📸 Capturas de Pantalla](#-capturas-de-pantalla)
  - [🤝 Contribuciones](#-contribuciones)
  - [⚖️ Licencia](#️-licencia)
  - [⚠️ Disclaimer](#️-disclaimer)
  - [📞 Soporte](#-soporte)

---

## 🎯 Descripción

**Password Security Tool** es una herramienta de ciberseguridad desarrollada en Python que proporciona un conjunto completo de funcionalidades para el análisis, generación y gestión segura de contraseñas. Diseñada para profesionales de la seguridad, administradores de sistemas y usuarios conscientes de la importancia de la seguridad digital.

## ✨ Características Principales

- 🔍 **Análisis Avanzado**: Evalúa la fortaleza de contraseñas con métricas detalladas
- 🎲 **Generación Segura**: Crea contraseñas criptográficamente seguras
- 🔐 **Gestor Cifrado**: Almacena contraseñas con cifrado AES-256
- 🌐 **Verificación HIBP**: Consulta la base de datos de Have I Been Pwned
- 📝 **Convertidor Inteligente**: Transforma frases memorables en contraseñas robustas
- 🎨 **Interfaz Moderna**: Banner ASCII profesional con colores
- 🛡️ **Seguridad Máxima**: No almacena datos sensibles en texto plano

## 🚀 Instalación

### Requisitos

- Python 3.7 o superior
- Conexión a internet (para verificación HIBP)
- Sistema operativo: Windows, macOS, Linux

### Instalación Rápida

1. **Clona el repositorio:**
```bash
git clone https://github.com/qius-alx/password_tools.git
cd password_tools
```

2. **Instala las dependencias:**
```bash
pip install -r requirements.txt
```

3. **Ejecuta la herramienta:**
```bash
python password_tool.py
```

## 📖 Uso

### Ejecutar la Herramienta

```bash
python password_tool.py
```

### Opciones Disponibles

Al ejecutar la herramienta, verás el siguiente menú:

```
┌──────────────────────────────────────────────────────────────────────┐
│                🔐 PASSWORD SECURITY TOOLKIT v2.0 🔐                 │
│                     Herramienta de Ciberseguridad                   │
└──────────────────────────────────────────────────────────────────────┘

[1] 🔍 Analizar contraseña         - Evalúa la fortaleza de tu contraseña
[2] 🎲 Generar contraseña segura   - Crea contraseñas aleatorias robustas  
[3] 🔐 Guardar/Gestionar contraseñas - Gestor cifrado de contraseñas
[4] 🌐 Verificar si está filtrada   - Consulta base de datos de brechas
[5] 📝 Convertir frase → contraseña - Transforma frases en contraseñas seguras
[0] 🚪 Salir                       - Terminar programa
```

## 🔧 Funcionalidades Detalladas

### 1. 🔍 Análisis de Contraseñas

Evalúa contraseñas basándose en:
- ✅ **Longitud** (mínimo recomendado: 12 caracteres)
- ✅ **Complejidad** (mayúsculas, minúsculas, números, símbolos)
- ❌ **Patrones comunes** (detección de secuencias inseguras)
- 📊 **Puntuación** (sistema de 0-6 puntos)

**Niveles de Seguridad:**
- 🟢 **FUERTE** (5-6 puntos): Contraseña robusta
- 🟡 **MEDIA** (3-4 puntos): Necesita mejoras
- 🔴 **DÉBIL** (0-2 puntos): Insegura, cambiar inmediatamente

### 2. 🎲 Generador de Contraseñas

- 🔢 **Longitud configurable** (4-128 caracteres)
- 🎛️ **Opciones personalizables**:
  - Incluir/excluir símbolos especiales
  - Garantía de al menos un carácter de cada tipo
- 🔐 **Seguridad criptográfica** usando `secrets` library
- 📊 **Análisis automático** de la contraseña generada

### 3. 🔐 Gestor de Contraseñas

**Características de Seguridad:**
- 🔒 **Cifrado AES-256** con Fernet
- 🔑 **Derivación de claves** PBKDF2 (100,000 iteraciones)
- 🧂 **Salt único** para cada instalación
- 👤 **Contraseña maestra** para acceso

**Funcionalidades:**
- ➕ Agregar nuevas contraseñas
- 👁️ Ver contraseñas almacenadas
- 🗑️ Eliminar entradas
- 🎲 Generación automática al agregar

### 4. 🌐 Verificación HIBP

Verifica si una contraseña aparece en filtraciones usando [Have I Been Pwned](https://haveibeenpwned.com/):

- 🔍 **k-Anonymity**: Solo envía los primeros 5 caracteres del hash SHA-1
- 🛡️ **Privacidad protegida**: La contraseña completa nunca sale del sistema
- 📊 **Estadísticas**: Muestra cuántas veces apareció en filtraciones
- 🌐 **API oficial**: Consulta directa a la base de datos de HIBP

### 5. 📝 Convertidor de Frases

Transforma frases memorables en contraseñas seguras:

**Reemplazos Inteligentes:**
- `a/A` → `@`
- `e/E` → `3`
- `i/I` → `!`
- `o/O` → `0`
- `s/S` → `$`
- `t/T` → `7`
- `l/L` → `1`
- `espacio` → `_`

**Ejemplo:**
- Entrada: `"Me gusta la pizza"`
- Salida: `"M3_gu$7@_l@_p!zz@47&"`

## 🛡️ Seguridad

Esta herramienta implementa las mejores prácticas de seguridad:

- 🔐 **Cifrado robusto**: AES-256 con Fernet
- 🔑 **Gestión de claves**: PBKDF2 con salt único
- 🔒 **Entrada segura**: `getpass` para contraseñas
- 🎲 **Aleatoriedad criptográfica**: `secrets` library
- 🚫 **Sin almacenamiento en texto plano**: Todo cifrado
- 🔍 **Verificación privada**: k-Anonymity para HIBP

## 📦 Dependencias

```txt
cryptography>=3.4.8
requests>=2.25.1
```

## 🔗 API Externa

- **Have I Been Pwned API**: `https://api.pwnedpasswords.com/`
  - Gratuita y sin límites de uso
  - No requiere registro ni API key
  - Implementa k-Anonymity para privacidad

## 📸 Capturas de Pantalla

<details>
<summary>🖼️ Ver capturas de pantalla</summary>

### Banner Principal
```
    ____                                     _   _______            _ 
   |  _ \ __ _ ___ ___ __      _____  _ __ __| | |__   __|___   ___ | |
   | |_) / _` / __/ __\ \ /\ / / _ \| '__/ _` |    | |/ _ \ \ / _ \| |
   |  __/ (_| \__ \__ \\ V  V / (_) | | | (_| |    | | (_) | | (_) | |
   |_|   \__,_|___/___/ \_/\_/ \___/|_|  \__,_|    |_|\___/  |_\___/|_|
```

### Análisis de Contraseña
```
📊 RESULTADO DEL ANÁLISIS:
Nivel de seguridad: 🟢 FUERTE
Puntuación: 6/6

📋 Detalles:
  ✅ Longitud adecuada (12+ caracteres)
  ✅ Contiene mayúsculas
  ✅ Contiene minúsculas
  ✅ Contiene números
  ✅ Contiene símbolos especiales
```

</details>

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Si quieres mejorar la herramienta:

1. 🍴 Fork el repositorio
2. 🌿 Crea una rama para tu feature (`git checkout -b feature/nueva-funcionalidad`)
3. 💻 Realiza tus cambios
4. ✅ Asegúrate de que todo funcione correctamente
5. 📝 Commit tus cambios (`git commit -am 'Añadir nueva funcionalidad'`)
6. 📤 Push a la rama (`git push origin feature/nueva-funcionalidad`)
7. 🔄 Abre un Pull Request

## ⚖️ Licencia

Este proyecto está licenciado bajo la Licencia MIT. Ver el archivo [LICENSE](LICENSE) para más detalles.

```
MIT License

Copyright (c) 2024 qius-alx

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files...
```

## ⚠️ Disclaimer

Esta herramienta está diseñada para uso educativo y profesional en entornos de ciberseguridad. Los desarrolladores no se hacen responsables del uso indebido de esta herramienta.

**Uso Responsable:**
- ✅ Auditorías de seguridad autorizadas
- ✅ Evaluación de contraseñas propias
- ✅ Educación en ciberseguridad
- ❌ Actividades ilegales o no autorizadas
