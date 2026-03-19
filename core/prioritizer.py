import pandas as pd
import os
from dotenv import load_dotenv

class Prioritizer:
    def __init__(self):
        load_dotenv()
        self.matrix_path = os.getenv('PATH_MATRIX')

    def aplicar_priorizacion(self, df_raw):
        """
        Replica el flujo de KNIME (Pivote, Join y Rule Engine).
        """
        if not os.path.exists(self.matrix_path):
            print(f"[!] Alerta: No se encontró la matriz en {self.matrix_path}. Se usará severidad original.")
            return df_raw

        # 1. Cargar la matriz de riesgos (Paso 1920 en KNIME)
        df_matrix = pd.read_csv(self.matrix_path)

        # 2. Separar CVEs (Equivalente a Cell Splitter 1931 + Unpivot 1912)
        # Limpiamos y expandimos los CVEs para el cruce
        df_raw['CVE'] = df_raw['CVE'].astype(str).replace('nan', '')
        df_expanded = df_raw.assign(CVE=df_raw['CVE'].str.split(',')).explode('CVE')
        df_expanded['CVE'] = df_expanded['CVE'].str.strip()

        # 3. Joiner (Paso 1927 en KNIME)
        # Cruzamos los resultados de Nessus con tu matriz nueva
        df_merged = pd.merge(
            df_expanded, 
            df_matrix[['cve', 'prediction', 'classification']], 
            left_on='CVE', 
            right_on='cve', 
            how='left'
        )

        # 4. Lógica de Recategorización (Pasos 1925 y 1922 en KNIME)
        def definir_severidad(row):
            # Si el CVE no estaba en la matriz (prediction es NaN)
            if pd.isna(row['prediction']):
                mapping = {
                    'Critical': 'Muy Crítica',
                    'High': 'Crítica',
                    'Medium': 'Alta',
                    'Low': 'Baja y Media'
                }
                return mapping.get(row['Risk'], 'Baja y Media')
            return row['classification']

        def definir_score(row):
            if pd.isna(row['prediction']):
                mapping_score = {
                    'Critical': 1.0,
                    'High': 0.74,
                    'Medium': 0.46,
                    'Low': 0.001
                }
                return mapping_score.get(row['Risk'], 0.001)
            return row['prediction']

        df_merged['nueva_severidad'] = df_merged.apply(definir_severidad, axis=1)
        df_merged['nuevo_score'] = df_merged.apply(definir_score, axis=1)

        # 5. Consolidación (Paso 1929 en KNIME)
        # Volvemos a agrupar por Plugin y Host para quedarnos con la vulnerabilidad más crítica encontrada
        df_final = df_merged.sort_values('nuevo_score', ascending=False).drop_duplicates(['Plugin ID', 'Host'])
        
        return df_final