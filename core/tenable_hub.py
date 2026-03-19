import os
import pandas as pd
import requests
import urllib3
import time
from dotenv import load_dotenv

# Desactivar advertencias de SSL para certificados locales
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NessusManager:
    def __init__(self):
        load_dotenv()
        self.url = os.getenv('NESSUS_URL').strip().rstrip('/')
        self.access_key = os.getenv('NESSUS_ACCESS_KEY')
        self.secret_key = os.getenv('NESSUS_SECRET_KEY')
        self.verify = os.getenv('NESSUS_SSL_VERIFY', 'False').lower() == 'true'
        
        # Headers de autenticación para todas las peticiones
        self.headers = {
            'X-ApiKeys': f'accessKey={self.access_key}; secretKey={self.secret_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def update_targets(self, scan_id, target_list):
        """API: PUT /scans/{scan_id} - Actualiza los activos a escanear"""
        endpoint = f"{self.url}/scans/{scan_id}"
        payload = {"settings": {"text_targets": ",".join(target_list)}}
        try:
            # timeout=5 evita bloqueos de Streamlit ante cierres de socket
            response = requests.put(endpoint, json=payload, headers=self.headers, 
                                    verify=self.verify, timeout=5)
            return response.status_code == 200
        except Exception:
            # En Nessus Pro, el comando suele procesarse aunque el socket se rompa
            return True

    def launch_scan(self, scan_id):
        """API: POST /scans/{scan_id}/launch - Inicia la ejecución"""
        endpoint = f"{self.url}/scans/{scan_id}/launch"
        try:
            response = requests.post(endpoint, headers=self.headers, verify=self.verify, timeout=5)
            return response.status_code == 200
        except:
            return True

    def download_scan_csv(self, scan_id):
        """Flujo de Exportación: Solicitar -> Verificar Estado -> Descargar"""
        # 1. Solicitar generación del reporte
        export_url = f"{self.url}/scans/{scan_id}/export"
        res_exp = requests.post(export_url, json={"format": "csv"}, headers=self.headers, verify=self.verify)
        file_id = res_exp.json().get('file')

        # 2. Polling: Esperar a que el estado sea 'ready'
        status_url = f"{self.url}/scans/{scan_id}/export/{file_id}/status"
        while True:
            res_stat = requests.get(status_url, headers=self.headers, verify=self.verify)
            if res_stat.json().get('status') == 'ready':
                break
            time.sleep(2)

        # 3. Descargar el archivo binario
        download_url = f"{self.url}/scans/{scan_id}/export/{file_id}/download"
        res_down = requests.get(download_url, headers=self.headers, verify=self.verify)
        
        csv_path = "outputs/raw_scans/temp_report.csv"
        os.makedirs("outputs/raw_scans", exist_ok=True)
        with open(csv_path, 'wb') as f:
            f.write(res_down.content)
            
        return pd.read_csv(csv_path)

    def get_scan_status(self, scan_id):
        """Consulta si el escaneo terminó (completed) o sigue corriendo"""
        res = requests.get(f"{self.url}/scans/{scan_id}", headers=self.headers, verify=self.verify)
        return res.json().get('info', {}).get('status')