import os
import pandas as pd
from tenable.nessus import Nessus
import urllib3
from dotenv import load_dotenv

# Silenciar advertencias de certificados autofirmados (SSL bypass)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NessusManager:
    def __init__(self):
        load_dotenv()
        self.url = os.getenv('NESSUS_URL')
        self.access_key = os.getenv('NESSUS_ACCESS_KEY')
        self.secret_key = os.getenv('NESSUS_SECRET_KEY')
        # Convertimos el string del .env a Booleano para el parámetro ssl_verify
        self.verify = os.getenv('NESSUS_SSL_VERIFY', 'False').lower() == 'true'
        
        # Inicialización de la conexión
        self.connection = Nessus(
            self.url, 
            access_key=self.access_key, 
            secret_key=self.secret_key,
            ssl_verify=self.verify
        )

    def update_targets(self, scan_id, target_list):
        """Actualiza la lista de IPs/Hostnames en el escaneo configurado"""
        targets = ",".join(target_list)
        self.connection.scans.edit(scan_id, settings={'text_targets': targets})
        return True

    def download_reports(self, scan_id):
        """
        Exporta y descarga los resultados del escaneo.
        Retorna un DataFrame con el CSV para procesamiento interno.
        """
        # 1. Exportar y descargar CSV (Para el procesamiento de datos)
        csv_path = os.getenv('PATH_RAW_CSV')
        with open(csv_path, 'wb') as fobj:
            self.connection.scans.export(scan_id, format='csv', fobj=fobj)
        
        # 2. Exportar PDF (Detalle para equipos de resolución)
        pdf_path = os.getenv('PATH_RAW_PDF')
        with open(pdf_path, 'wb') as fobj:
            self.connection.scans.export(scan_id, format='pdf', fobj=fobj)

        # 3. Exportar HTML (Alternativo para intervención)
        html_path = os.getenv('PATH_RAW_HTML')
        with open(html_path, 'wb') as fobj:
            self.connection.scans.export(scan_id, format='html', fobj=fobj)
            
        return pd.read_csv(csv_path)