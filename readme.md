# SISTEMA DE ESCANEO DE VULNERABILIDADES Y HARDENING
## Documentación Completa - Fullstack 3 Duoc

---

## 🚀 ESTADO DEL PROYECTO (MVP - Worker Local)
Llevamos avanzado lo siguiente:
- Worker programado en Python, independiente y containerizado en Docker.
- Script de escaneo de red con Nmap corriendo y descubriendo máquinas vivas y puertos.
- Script de auditorías locales (Hardening) que lee linux con Lynis y procesa los logs.
- Estructura y conexión API terminada para pedir tareas a un servidor externo de GVM (OpenVAS). 
- Archivo compose propio para el servidor de GVM (aislado para no matar de RAM al cliente).
- Generación de todo este reporte consolidado a un archivo JSON limpio, listo para que nuestro Backend de Java lo consuma por RabbitMQ.

---

## 📚 ESTRUCTURA DE DOCUMENTACIÓN

Este proyecto contendrá **3 documentos principales** que cubren todos los aspectos de la arquitectura:

### 1. **`proyecto_arquitectura.md`** - ARQUITECTURA Y DIAGRAMAS
**Contenido:**
- [x] Diagrama de arquitectura general
- [ ] Flujo de operación principal (step-by-step)
- [ ] Diagrama de comunicación entre microservicios
- [ ] Diagrama de interconexión de microservicios
- [ ] Estructura de directorios del proyecto
- [ ] Diagrama de seguridad y autenticación
- [ ] Ejemplo de dashboard y visualizaciones
- [ ] Tech stack final recomendado
- [ ] Próximos pasos sugeridos

### 2. **`eventos_y_schemas.md`** - EVENTOS Y ESPECIFICACIONES TÉCNICAS
**Contenido:**
- [ ] Tipos de eventos definidos completamente:
    - `job.created`
    - `scan.started`
    - `hosts.discovered`
    - `vulnerabilities.detected`
    - `hardening.checked`
    - `scan.completed`
    - `recommendations.generated`
- [ ] Ejemplos JSON reales para cada evento
- [ ] Diagrama temporal de eventos (Timeline)
- [ ] Diagramas de casos de uso (Use Cases)
- [ ] Endpoints REST por microservicio
- [ ] Ejemplos de Request/Response
- [ ] Flujo completo documentado

### 3. **`implementacion_detallada.md`** - GUÍA DE IMPLEMENTACIÓN
**Contenido:**

### Objetivo del Proyecto
Sistema tipo **Nessus de código abierto** para escaneo de vulnerabilidades en redes locales, con capacidad de:
- 🔍 **Descubrimiento de hosts** (Nmap)
- 🔴 **Evaluación de vulnerabilidades** (GVM)
- 🛡️ **Auditoría de hardening** (Lynis + CIS Benchmarks)
- 🤖 **Recomendaciones con IA** (Por definir)
- 📅 **Escaneos programados** (Jobs scheduler)
- 📈 **Históricos y tendencias** (Tracking temporal)

### Tecnologías
- **Frontend:** React + TypeScript + Tailwind
- **Backend:** Springboot
- **Worker:** Python 3.10+
- **BD:** PostgreSQL + MongoDB + Redis
- **Queue:** RabbitMQ
- **Containerización:** Docker + Docker Compose
- **IA:** Claude API

### Estimación de Esfuerzo
- **Total:** ~446 horas (1 dev)
- **Timeline:** 8 semanas a full-time, 10-12 semanas realista (O hasta donde llegue a final de semestre 😊)
- **MVP:** Semanas 1-6
- **Bonus:** Semana 8 (MS-IA)

---

## 🗂️ ESTRUCTURA DEL PROYECTO

```text
vulnanalytics/
│
├── frontend/                    # React app (pendiente)
│
├── backend/                     # Springboot (pendiente)
│
├── services/
│   ├── gvm/                     # Servidor Pesado de escaneo
│   │   └── docker-compose.yml   
│   │
│   └── worker/                  # Agente Python de escaneo local
│       ├── app/
│       │   ├── scanner/
│       │   │   ├── network_scanner.py
│       │   │   ├── hardening_scanner.py
│       │   │   └── vuln_scanner_gvm.py
│       │   ├── manual_runner.py
│       │   └── requirements.txt
│       ├── Dockerfile
│       └── docker-compose-worker.yml
│
└── docs/                        # Documentación
```

---

## 🔑 CONCEPTOS CLAVE

### **Microservicios**
- Cada dominio de negocio tiene su propio servicio
- Independientes en deployment
- Responsables de su propia BD

### **Asincronía**
- Jobs se ejecutan en Worker (red local)
- Resultados se publican como eventos
- Frontend escucha via WebSocket

### **Persistence**
- PostgreSQL: datos transaccionales (auth, hosts, jobs)
- MongoDB: documentos flexibles (vulns, hardening, reports)
- Redis: cache y sessions

### **Seguridad**
- JWT para autenticación
- Role-Based Access Control (RBAC)
- Auditoría completa de acciones