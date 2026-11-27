# NetLab Auditor — Proyecto 4 (Redes II)

Sistema web de auditoría de red local, mapeo de topología en tiempo real y análisis de seguridad para un router Wi-Fi físico (sin máquinas virtuales).

## Stack Tecnológico

* **Backend:** Python, FastAPI, Uvicorn, `python-nmap`, Scapy, `fpdf2` y SQLite.
* **Frontend:** React + Vite con mapa radial interactivo en SVG nativo (funciona 100% offline en red local).

---

## Estructura del Proyecto

```text
proyecto4-auditor/
├── backend/
│   ├── main.py                # API REST (FastAPI) y rutas principales
│   ├── nmap_scanner.py        # Motor Nmap (Top 20, Top 50, -sV, -O, ARP, ICMP, UDP)
│   ├── router_auditor.py      # Auditoría específica del Router Wi-Fi y scripts NSE
│   ├── scapy_topology.py      # Barrido ARP en Capa 2, fabricante offline y Traceroute
│   ├── whitelist_manager.py   # Gestión de dispositivos autorizados por MAC
│   ├── history_db.py          # Persistencia de escaneos en SQLite
│   ├── report_generator.py    # Exportación de reportes en JSON, CSV y PDF
│   └── requirements.txt       # Dependencias de Python
└── frontend/
    └── src/
        ├── App.jsx            # Orquestador principal y manejo de pestañas
        ├── index.css          # Estilos de la interfaz
        ├── services/
        │   └── api.js         # Cliente HTTP hacia el backend FastAPI
        ├── utils/
        │   ├── scanPresets.js # Perfiles y comandos Nmap
        │   └── formatters.js  # Etiquetas de riesgo y tipos de dispositivo
        └── components/        # Componentes modulares (Topología, Hosts, Router, Whitelist, Historial)
```

---

## Requisitos Previos (Instalar una sola vez)

1. **Python 3.12 o superior** (recomendado 3.12 / 3.13) con la opción *Add Python to PATH* marcada.
2. **Nmap 7.9+** con **Npcap** incluido:
   * Al instalar Npcap, marcar obligatoriamente la casilla **"Install Npcap in WinPcap API-compatible Mode"** (necesario para que Scapy funcione en Windows).
3. **Node.js (versión LTS)** desde [nodejs.org](https://nodejs.org/) (incluye `npm`).
4. **VS Code o Terminal ejecutados como Administrador** (obligatorio para escaneos TCP Stealth `-sS`, detección de SO `-O` y paquetes ARP con Scapy).

---

## Cómo ejecutar el proyecto paso a paso

### 1. Clonar o actualizar el repositorio
```powershell
git clone <URL_DEL_REPOSITORIO>
cd proyecto4-auditor
```
*(Si ya lo tienes clonado, solo actualiza con `git pull origin main`).*

### 2. Levantar el Backend (Terminal 1 — Como Administrador)
```powershell
cd backend
py -m venv venv
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
* **Verificación:** Al abrir `http://127.0.0.1:8000/docs` debe cargar el panel interactivo de Swagger UI.
* *(Las próximas veces solo ejecuta el último comando `uvicorn` dentro de `backend`).*

### 3. Levantar el Frontend (Terminal 2)
Abre una segunda terminal en la carpeta raíz del proyecto:
```powershell
cd frontend
npm install
npm run dev
```
* **Verificación:** Abre `http://localhost:5173` en tu navegador. La esquina superior derecha debe mostrar **Backend Online · FastAPI** en verde.
* *(Las próximas veces solo ejecuta `npm run dev` dentro de `frontend`).*

---

## Configuración para pruebas con el Router Wi-Fi físico

1. Enchufa el router Wi-Fi solo a la corriente eléctrica (no hace falta conectar cable en el puerto WAN/Internet).
2. Conecta la laptop auditora preferiblemente por **cable Ethernet a un puerto LAN (1-4)** del router, o al Wi-Fi del router. Desconecta otras redes o VPNs.
3. Conecta 2 o 3 equipos de prueba (laptops y celulares) al Wi-Fi del router (aceptar *"Mantener conexión sin internet"*).
4. Ejecuta `ipconfig` en CMD y confirma que recibiste una IP privada válida (ej. `192.168.0.x`) y una **Puerta de enlace predeterminada** (ej. `192.168.0.1`).
5. Recarga `http://localhost:5173` y ejecuta los escaneos (Top 20, Top 50, Servicios `-sV`, Scapy ARP o Auditoría del Router).

---

## Endpoints principales de la API

* `GET /api/status` — Estado del servidor, IP local, Gateway del router y subred detectada.
* `POST /api/scan` — Escaneo Nmap (perfiles predefinidos o argumentos personalizados).
* `POST /api/audit-router` — Auditoría específica del router Wi-Fi (puertos críticos, NSE y riesgo).
* `POST /api/topology/scapy` — Mapeo rápido ARP en Capa 2 con Scapy.
* `GET /api/topology/traceroute/{target_ip}` — Trazado de saltos hacia una IP con Scapy.
* `GET / POST / DELETE /api/whitelist` — Gestión de direcciones MAC autorizadas.
* `GET /api/history` y `GET /api/history/{scan_id}` — Historial almacenado en SQLite.
* `GET /api/export/{scan_id}/{json|csv|pdf}` — Descarga de reportes.

---

## Solución rápida a problemas comunes

* **`npm` no se reconoce o PowerShell bloquea scripts:** Cierra y vuelve a abrir VS Code tras instalar Node.js, o usa `npm.cmd install` y `npm.cmd run dev`.
* **Error de Scapy (`Error opening adapter`):** Reinstala Npcap marcando *"WinPcap API-compatible Mode"* y asegúrate de abrir la terminal como **Administrador**.
* **`ipconfig` muestra `169.254.x.x` sin puerta de enlace:** El cable está en el puerto WAN o el DHCP del router está desactivado; cámbialo a un puerto LAN (1-4) o reinicia el router.