S.A.R.A. — CerberusOps SOAR v4.0

S.A.R.A. (Security Orchestration, Automation, and Response) es una plataforma de orquestación, automatización y respuesta de seguridad alojada de forma local (self-hosted). Está diseñada para agilizar la ingesta de telemetría de red, auditar la seguridad del sistema operativo, evaluar inteligencia de amenazas y ejecutar respuestas automáticas de contención mediante modelos de Inteligencia Artificial locales y reglas perimetrales.
Arquitectura y Tecnologías

El sistema está completamente contenerizado mediante Docker Compose y consta de los siguientes componentes principales:

    S.A.R.A. Core (Backend API & SOC Dashboard):

        Python 3.12 / FastAPI: API RESTful de alta velocidad para ingesta de logs, gestión de eventos y orquestación.

        Streamlit: Dashboard visual e interactivo para la supervisión del estado del SOC en tiempo real.

        SQLite: Base de datos relacional para el registro histórico de incidentes, trazabilidad y auditorías del sistema.

        FPDF2: Generador pericial de dictámenes forenses y reportes ejecutivos en PDF con firmas de integridad criptográfica mediante hash SHA-256.

    Motor de Automatización:

        n8n: Orquestación de flujos de trabajo (workflows) mediante webhooks e ingesta remota de alertas.

    Inteligencia Artificial Local:

        Ollama (qwen2.5:3b): Modelo de lenguaje local optimizado para triaje técnico de incidentes de ciberseguridad, evaluación del impacto y mapeo directo a vectores del marco MITRE ATT&CK con respuesta rápida en hardware con restricciones de VRAM.

    Herramientas Perimetrales y Hardening:

        Lynis: Auditorías automatizadas de seguridad y endurecimiento del sistema operativo host.

        AbuseIPDB: Consulta en tiempo real de la reputación y nivel de confianza de direcciones IP maliciosas.

        UFW (Uncomplicated Firewall): Bloqueo dinámico perimetral y gestión de listas blancas de direcciones IP.

Metodología de Desarrollo: Scrum

El desarrollo de la plataforma S.A.R.A. se gestionó bajo la metodología ágil Scrum, implementando un enfoque iterativo e incremental a lo largo de ciclos de trabajo (Sprints):

    Product Backlog: Priorización de requerimientos funcionales (API de ingesta con FastAPI, integración del motor Ollama con qwen2.5:3b, módulo de respuestas UFW, generación de dictámenes forenses en PDF y dashboard interactivo en Streamlit).

    Sprints e Incrementos:

        Sprint 1: Diseño de la arquitectura base, endpoints RESTful con FastAPI y esquema de base de datos relacional en SQLite.

        Sprint 2: Contenerización con Docker Compose, despliegue de n8n e integración con la IA local utilizando el modelo qwen2.5:3b.

        Sprint 3: Incorporación de Threat Intelligence (AbuseIPDB), auditorías automatizadas del sistema operativo con Lynis y generación de reportes forenses con hash SHA-256.

        Sprint 4: Integración del Dashboard interactivo en Streamlit con visualización de telemetría de red, optimización de la interfaz en español, configuración del archivo app.py y pruebas de integración finales.

Inicio Rápido
Prerrequisitos

    Sistema Operativo Linux (Ubuntu 22.04 / 24.04 recomendados)

    Docker y Docker Compose instalados

    Ollama configurado localmente con el modelo qwen2.5:3b (ollama pull qwen2.5:3b)

Pasos de Despliegue

    Clonar el repositorio:
    Bash

    git clone https://github.com/joshuatepox-debug/S.A.R.A.git
    cd S.A.R.A

    Iniciar el servicio de Docker y los contenedores:
    Bash

    sudo systemctl start docker
    sudo docker compose up -d

    Acceso a los Servicios:

        Dashboard SOC (Streamlit): http://localhost:8501

        Documentación de la API (Swagger - FastAPI): http://localhost:8000/docs

        Orquestador n8n: http://localhost:5678

        Motor de IA (Ollama): http://localhost:11434

Licencia y Uso Académico

Proyecto desarrollado para la evaluación académica en la Facultad de Ciencias de la Computación — Universidad Autónoma de Puebla (BUAP).
