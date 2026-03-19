import subprocess
import pandas as pd
from datetime import datetime

class ScannerService:
    def verify_reachability(self, ip_list, reach_path):
        results = []
        for ip in ip_list:
            # Comando ping para Windows (1 paquete, 1 seg de espera)
            res = subprocess.call(['ping', '-n', '1', '-w', '1000', ip], 
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            status = "Alcanzable" if res == 0 else "No Alcanzable"
            results.append({"IP": ip, "Estado": status, "Fecha": datetime.now()})
        
        df_reach = pd.DataFrame(results)
        df_reach.to_csv(reach_path, index=False)
        alcanzados = df_reach[df_reach['Estado'] == 'Alcanzable'].shape[0]
        return df_reach, alcanzados