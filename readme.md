# SISTEMA DE ESCANEO DE VULNERABILIDADES Y HARDENING
## Documentación Completa - Fullstack 3 Duoc

---

## 🚀 ESTADO DEL PROYECTO (Fase Worker Completada)
Llevamos avanzado lo siguiente:
- [x] Agente Worker programado en Python (Arquitectura Productor-Consumidor).
- [x] Motor de red con **Nmap** (Top 1000 puertos, descubrimiento de hosts y servicios).
- [x] Auditoría de configuración local (Hardening) usando **Lynis**.
- [x] Servidor pesado **GVM/OpenVAS** dockerizado y vinculado vía protocolo nativo GMPv22.
- [x] Soporte para **Escaneos Autenticados (Caja Blanca)** mediante inyección de credenciales dinámicas (SMB/SSH) a GVM.
- [x] Cola de mensajería **RabbitMQ** integrada. El Worker funciona 100% como consumidor asíncrono para escaneos de larga duración (Heartbeat=0).
- [x] Exportación de reporte maestro consolidado a JSON para consumo de Java.

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
│   ├── gvm/                     # Motor GVM / OpenVAS (176k Firmas)
│   │   └── docker-compose.yml   
│   │
│   ├── queue/                   # Broker de mensajeria
│   │   └── docker-compose.yml   # Contenedor RabbitMQ
│   │
│   └── worker/                  # Agente Consumidor Python
│       ├── app/
│       │   ├── scanner/
│       │   │   ├── network_scanner.py
│       │   │   ├── hardening_scanner.py
│       │   │   └── vuln_scanner_gvm.py
│       │   ├── queue_producer_mvp.py
│       │   ├── worker_consumer.py
│       │   ├── manual_runner.py
│       │   └── requirements.txt
│       ├── Dockerfile
│       └── docker-compose-worker.yml
│
└── docs/                        # Documentacion
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