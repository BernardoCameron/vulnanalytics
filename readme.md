# SISTEMA DE ESCANEO DE VULNERABILIDADES Y HARDENING
## Documentación Completa - Fullstack 3 Duoc

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

```
vulnanalytics/
│
├── frontend/                    # React app
│   ├── src/components
│   ├── src/pages
│   └── Dockerfile
│
├── backend/
│   ├── api-gateway/
│   ├── services/
│   │   ├── ms-auth/
│   │   ├── ms-inventario/
│   │   ├── ms-orquestador/
│   │   ├── ms-vulnerabilidades/
│   │   ├── ms-hardening/
│   │   └── ms-ia/
│   └── shared/
│
├── worker/ 
│   ├── src/
│   │   ├── scanners/
│   │   └── queue_consumer.py
│   └── Dockerfile
│
├── docker-compose.yml          # Orquestación local
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

---