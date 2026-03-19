import streamlit as st
import os
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
from core.orchestrator import ScanOrchestrator
from core.notifier import Notifier

# Configuración visual de la página
st.set_page_config(page_title="Gestión de Vulnerabilidades - Engineer Dashboard", layout="wide")
load_dotenv()

st.title("🛡️ Sistema de Gestión de Vulnerabilidades")
st.markdown("---")

# Inicializar clases
orchestrator = ScanOrchestrator()
notifier = Notifier()

# --- Barra Lateral: Estado de Configuración ---
st.sidebar.header("⚙️ Estado de Configuración")
config_files = {
    "Inventario": os.getenv('PATH_INVENTORY'),
    "Matriz KNIME": os.getenv('PATH_MATRIX'),
    "Asumidos": os.getenv('PATH_ASSUMED'),
    "Snapshot (Foto)": os.getenv('PATH_SNAPSHOT')
}

for name, path in config_files.items():
    if os.path.exists(path):
        st.sidebar.success(f"✅ {name} listo")
    else:
        st.sidebar.warning(f"⚠️ {name} no encontrado")

# --- Cuerpo Principal: Pestañas de Trabajo ---
tab1, tab2, tab3 = st.tabs(["🚀 Inicio de Ciclo", "📊 Seguimiento Semanal", "📜 Auditoría"])

with tab1:
    st.header("Inicio de Ciclo Trimestral")
    st.info("Esta acción actualizará los targets en Nessus, ejecutará el escaneo y creará la **Foto Inicial (Snapshot)** con la revalorización aplicada.")
    
    if st.button("Lanzar Snapshot Inicial"):
        with st.spinner("Ejecutando proceso completo (Pasos 1-8)..."):
            try:
                df_snap = orchestrator.ejecutar_pasos_iniciales()
                st.success("✅ Snapshot Inicial generado y guardado exitosamente.")
                st.dataframe(df_snap.head(20))
                
                # Enviar notificación opcional
                notifier.enviar_reporte(
                    "INICIO DE CICLO: Snapshot Generado",
                    "Se ha generado la foto inicial del trimestre. Se adjunta la sábana priorizada.",
                    adjuntos=[os.getenv('PATH_SNAPSHOT')]
                )
            except Exception as e:
                st.error(f"Error en la ejecución: {e}")

with tab2:
    st.header("Verificación de Cierre (Semanal)")
    st.write("Compara el escaneo actual contra el Snapshot y descuenta los activos en el archivo de Asumidos.")
    
    if st.button("Ejecutar Comparativa de Estados"):
        with st.spinner("Analizando brechas y cierres..."):
            try:
                df_final = orchestrator.ejecutar_verificacion_semanal()
                st.success("✅ Verificación completada.")
                
                # Mostrar resumen de estados
                resumen = df_final['Estado'].value_counts()
                st.subheader("Resumen de Hallazgos")
                st.write(resumen)
                
                st.dataframe(df_final)

                # Notificación automática
                notifier.enviar_reporte(
                    "REPORTE SEMANAL: Seguimiento de Vulnerabilidades",
                    f"Resumen de estados:\n{resumen.to_string()}\n\nSe adjunta la sábana completa.",
                    adjuntos=[os.getenv('PATH_RAW_CSV'), os.getenv('PATH_RAW_PDF')]
                )
            except Exception as e:
                st.error(f"Error en la verificación: {e}")

with tab3:
    st.header("Evidencia de Auditoría (Logs)")
    log_path = os.getenv('PATH_LOGS')
    if os.path.exists(log_path):
        with open(log_path, "r") as f:
            st.text_area("Historial de pasos ejecutados:", f.read(), height=400)
    else:
        st.info("Aún no se han generado registros de auditoría.")