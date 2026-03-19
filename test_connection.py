import os
import urllib3
from tenable.nessus import Nessus
from dotenv import load_dotenv

# Silenciar advertencias de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def probar_conexion():
    load_dotenv()
    url = os.getenv('NESSUS_URL').strip().rstrip('/')
    access = os.getenv('NESSUS_ACCESS_KEY')
    secret = os.getenv('NESSUS_SECRET_KEY')
    scan_id = os.getenv('NESSUS_SCAN_ID')

    print(f"--- Diagnóstico de Conexión ---")
    print(f"URL: {url}")
    print(f"Scan ID objetivo: {scan_id}")
    
    try:
        # Inicialización básica sin sesiones complejas para descartar
        nessus = Nessus(
            url=url, 
            access_key=access, 
            secret_key=secret, 
            ssl_verify=False
        )
        
        print("\n1. Intentando listar escaneos disponibles...")
        scans = nessus.scans.list()
        print("✅ Conexión exitosa. Escaneos encontrados:")
        
        found = False
        for s in scans:
            print(f"   - ID: {s['id']} | Nombre: {s['name']} | Status: {s['status']}")
            if str(s['id']) == str(scan_id):
                found = True
        
        if found:
            print(f"\n2. ✅ El Scan ID {scan_id} fue localizado correctamente.")
        else:
            print(f"\n2. ❌ ERROR: El Scan ID {scan_id} NO existe en este servidor.")

    except Exception as e:
        print(f"\n❌ FALLO CRÍTICO: {e}")

if __name__ == "__main__":
    probar_conexion()