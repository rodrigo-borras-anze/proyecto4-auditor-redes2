# Proyecto 4 — Auditor de Red y Mapeo de Topología (Redes II)

## Requisitos previos
- Python 3.12+ (recomendado 3.12 o 3.13)
- Nmap 7.9+ con Npcap instalado y agregado al PATH
- Ejecutar la terminal/VS Code como **Administrador**

## Cómo levantar el Backend
```powershell
cd backend
py -m venv venv
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload