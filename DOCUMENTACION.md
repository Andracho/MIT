# Documentación Técnica - Suite IT Professional v5.0

## 1. Introducción
Suite IT Professional es una herramienta GUI escrita íntegramente en PowerShell utilizando Windows Forms. Su objetivo es centralizar tareas comunes de soporte técnico, administración de sistemas y auditoría de seguridad en una sola interfaz amigable y eficiente.

## 2. Arquitectura
El proyecto consiste en un script monolítico principal (`MIT4.ps1`) que maneja:
- **UI**: Windows Forms (System.Windows.Forms).
- **Lógica**: PowerShell nativo y llamadas a .NET.
- **Modularidad**: Uso de `TabControl` para separar contextos (Red, Usuarios, Seguridad, etc.).

### Archivos Clave
- `MIT4.ps1`: Script principal.
- `Logo.ico`: Icono de la aplicación.
- `Logo.png`: Recurso gráfico para branding.
- `config.json`: (Generado en `%LOCALAPPDATA%`) Persistencia de configuración.

## 3. Módulos Principales

### 3.1 🌐 Red
Gestión avanzada de networking.
- **Estructura**: Menú desplegable con 13 categorías.
- **Funciones**: Ping, Traceroute, DNS, Gestión de Adaptadores, WiFi, Proxy.

### 3.2 🛡️ Ciberseguridad (Nuevo)
Módulo preventivo inspirado en principios de Blue Team.
- **Dashboard**: Vista rápida de exposición (puertos abiertos, shares).
- **Auditoría**: Detección de configuración débil (SMBv1, Firewall desactivado).
- **Reportes**: Generación automática de informes en texto plano.

### 3.3 💻 Sistema & Mantenimiento
Herramientas de limpieza y diagnóstico.
- Liberación de espacio.
- Información de Hardware (WMI/CIM).
- Gestión de Procesos y Servicios.

## 4. Seguridad y Permisos
- **Elevación**: El script verifica privilegios de Administrador al inicio. Si se ejecuta como usuario estándar, muestra un panel de advertencia amarillo y deshabilita funciones críticas.
- **Evaluación de Riesgo**: Cada botón/función tiene asignado un nivel de riesgo (Bajo, Medio, Alto).
    - **Alto**: Requiere confirmación explícita del usuario.
    - **Panel Lateral**: Muestra el riesgo antes de ejecutar la acción al pasar el mouse.

## 5. Instalación y Despliegue
No requiere instalación. Es portable.
1. Copiar la carpeta del proyecto.
2. Ejecutar `MIT4.ps1` con PowerShell (Click derecho -> Ejecutar con PowerShell).
   - *Nota*: Puede requerir `Set-ExecutionPolicy Bypass` si las políticas de ejecución son restrictivas.

## 6. Soporte
Desarrollado por **Andrés Suárez (Andrachox)**.
Reportar bugs o sugerencias al correo de contacto o repositorio.
