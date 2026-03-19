import pandas as pd
import os
from dotenv import load_dotenv

class Analyzer:
    def __init__(self):
        load_dotenv()
        self.path_snapshot = os.getenv('PATH_SNAPSHOT')
        self.path_assumed = os.getenv('PATH_ASSUMED')

    def generar_seguimiento(self, df_actual):
        """
        Compara el escaneo actual contra la Foto Inicial y los Asumidos.
        """
        # 1. Cargar Foto Inicial (Snapshot)
        if not os.path.exists(self.path_snapshot):
            print("[!] No hay Snapshot Inicial. El resultado actual se tratará como base.")
            df_actual['Estado'] = 'Abierto'
            return df_actual
        
        df_inicial = pd.read_csv(self.path_snapshot)
        
        # 2. Cargar Asumidos
        # Campos: IP, Plugin Name, cve, criticidad, fecha asumido
        df_asumidos = pd.read_csv(self.path_assumed) if os.path.exists(self.path_assumed) else pd.DataFrame()

        # 3. Identificar CERRADOS
        # (Vulnerabilidades que estaban en el inicial pero no en el actual)
        # Usamos un set de llaves (IP + Plugin ID) para comparar
        keys_actual = set(zip(df_actual['Host'], df_actual['Plugin ID']))
        
        df_inicial['Estado'] = df_inicial.apply(
            lambda x: 'Cerrado' if (x['Host'], x['Plugin ID']) not in keys_actual else 'Persistente', 
            axis=1
        )
        
        # 4. Procesar el reporte ACTUAL (Abiertos y Asumidos)
        def determinar_estado_actual(row):
            # Verificar si está en la lista de asumidos
            if not df_asumidos.empty:
                # Coincidencia por IP y CVE
                match = df_asumidos[
                    (df_asumidos['IP'] == row['Host']) & 
                    (df_asumidos['cve'] == row['CVE'])
                ]
                if not match.empty:
                    return 'Asumido'
            return 'Abierto'

        df_actual['Estado'] = df_actual.apply(determinar_estado_actual, axis=1)

        # 5. Consolidar Sábana Única
        # Unimos los cerrados del inicial con los hallazgos del actual
        df_cerrados = df_inicial[df_inicial['Estado'] == 'Cerrado']
        reporte_final = pd.concat([df_actual, df_cerrados], ignore_index=True)

        return reporte_final