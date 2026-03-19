import os
import pandas as pd
from core.tenable_hub import NessusManager
from core.prioritizer import Prioritizer
from core.scanner_service import ScannerService

class ScanOrchestrator:
    def __init__(self, scope):
        self.scope = scope # 'NET' o 'SERV'
        self.nessus = NessusManager()
        self.prioritizer = Prioritizer()
        self.scanner = ScannerService()
        
        # Rutas y IDs dinámicos según el .env
        self.inv_path = os.getenv(f'PATH_INVENTORY_{scope}')
        self.scan_id = os.getenv(f'NESSUS_SCAN_ID_{scope}')
        self.reach_path = os.getenv(f'PATH_REACHABILITY_{scope}')
        self.snapshot_path = f"outputs/history/snapshot_{scope.lower()}.csv"

    def ejecutar_fase_1(self):
        """Verificación de Ping (Alcance)"""
        df_inv = pd.read_csv(self.inv_path)
        return self.scanner.verify_reachability(df_inv['direccionIP'].tolist(), self.reach_path)

    def ejecutar_fase_2(self):
        """Inyección en Nessus y Disparo"""
        df_reach = pd.read_csv(self.reach_path)
        vivos = df_reach[df_reach['Estado'] == 'Alcanzable']['IP'].tolist()
        
        if not vivos:
            return False

        # Actualizamos y lanzamos usando la API directa
        self.nessus.update_targets(self.scan_id, vivos)
        self.nessus.launch_scan(self.scan_id)
        return True

    def ejecutar_fase_3(self):
        """Descarga de datos y aplicación de lógica de priorización"""
        df_raw = self.nessus.download_scan_csv(self.scan_id)
        df_final = self.prioritizer.aplicar_priorizacion(df_raw)
        df_final.to_csv(self.snapshot_path, index=False)
        return df_final