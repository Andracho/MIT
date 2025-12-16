# Changelog - Suite IT Professional

Todas las mejoras y cambios notables de este proyecto serán documentados en este archivo.

## [5.0.0-final] - 2025-12-15

### Agregado 🚀
- **Nuevo Módulo de Ciberseguridad Preventiva**:
    - Dashboard Ejecutivo (Snapshot de Red, Auditoría, Estado Firewall).
    - Reportes Preventivos (Generación de TXT).
    - Geolocalización Ética (Consulta IP pública).
    - Tracking Interno (Logs de red).
    - Dashboard de Riesgo (Semáforo de seguridad).
- **Panel Global de Información**:
    - Barra lateral derecha persistente.
    - Muestra descripciones detalladas y nivel de riesgo al pasar el mouse por cualquier función.
- **Branding**:
    - Integración de Logo (Icono de ventana y Marca de agua en panel).
- **Interfaz Moderna**:
    - Tema oscuro (Dark Mode) unificado.
    - Diálogo "Acerca de" renovado con pestañas y mejor legibilidad.
    - Soporte para Scroll en pestañas con mucho contenido.

### Cambiado 🔄
- **Tab Red**:
    - Refactorizado a modelo modular con ComboBox.
    - 13 categorías de herramientas de red.
    - Optimización de carga de funciones.
- **Manejo de Errores**:
    - Solución a problemas de "Variable Scope" en eventos dinámicos.
    - Mejor captura de excepciones en módulos de reporte.

### Corregido 🐛
- Visibilidad de texto en ventana "Acerca de".
- Referencias inválidas en bucles de auditoría (`$k:` -> `$($k):`).
