import streamlit as st
import pandas as pd
import os
from core.orchestrator import ScanOrchestrator

# Configuración de página
st.set_page_config(page_title="Vulnerability Manager Pro", layout="wide")

# --- BARRA LATERAL: SELECTOR DE REGULATORIO ---
st.sidebar.title("🎯 Alcance de Control")
regulatorio = st.sidebar.selectbox(
    "Seleccione el Regulatorio:",
    ["NET", "SERV"],
    help="NET: Networking | SERV: Servidores"
)

# Inicializar Orquestador con el scope seleccionado
orchestrator = ScanOrchestrator(regulatorio)

st.title(f"🛡️ Gestión de Vulnerabilidades: {regulatorio}")
st.markdown(f"**Escaneo Asociado (Nessus ID):** `{orchestrator.scan_id}`")
st.divider()

# --- CUERPO PRINCIPAL: FASES ---
tab1, tab2 = st.tabs(["🚀 Inicio de Ciclo (Snapshot)", "📊 Seguimiento Semanal"])

with tab1:
    st.info(f"Ejecute las fases en orden para el regulatorio **{regulatorio}**.")
    
    col1, col2, col3 = st.columns(3)

    # --- FASE 1: PING TEST ---
    with col1:
        st.subheader("Fase 1: Alcance")
        if st.button(f"🔍 Validar IPs {regulatorio}", use_container_width=True):
            with st.spinner("Haciendo Ping..."):
                df_reach, total = orchestrator.ejecutar_fase_1()
                st.success(f"Activos Alcanzados: {total}")
                st.dataframe(df_reach, height=300)
                st.caption(f"Evidencia guardada en: `{orchestrator.reach_path}`")

    # --- FASE 2: LANZAR NESSUS ---
    with col2:
        st.subheader("Fase 2: Ejecución")
        st.write("Inyecta IPs vivas y dispara el escaneo.")
        if st.button("🚀 Lanzar en Nessus", use_container_width=True):
            if os.path.exists(orchestrator.reach_path):
                if orchestrator.ejecutar_fase_2():
                    st.warning("⚠️ Escaneo iniciado. Espere a que termine en la consola de Nessus antes de la Fase 3.")
                else:
                    st.error("No hay IPs alcanzables en el log de la Fase 1.")
            else:
                st.error("Primero debe ejecutar la Fase 1.")

    # --- FASE 3: SNAPSHOT ---
    with col3:
        st.subheader("Fase 3: Snapshot")
        st.write("Descarga resultados y aplica Lógica KNIME.")
        if st.button("💾 Generar Snapshot", use_container_width=True):
            with st.spinner("Procesando datos..."):
                try:
                    df_snap = orchestrator.ejecutar_fase_3()
                    st.success("✅ Snapshot generado exitosamente.")
                    st.dataframe(df_snap.head(10))
                except Exception as e:
                    st.error(f"Error: Asegúrese de que el escaneo en Nessus haya terminado. {e}")

with tab2:
    st.header("Cruce de Datos Semanal")
    st.write(f"Esta sección compara el estado actual de **{regulatorio}** contra su Snapshot trimestral.")
    
    if st.button("📈 Ejecutar Comparativa Actual"):
        with st.spinner("Cruzando datos..."):
            # Aquí llamamos al analyzer usando el snapshot_path específico del scope
            # (Asumiendo que el escaneo ya terminó en Nessus)
            df_actual = orchestrator.nessus.download_scan_csv(orchestrator.scan_id)
            df_priorizado = orchestrator.prioritizer.aplicar_priorizacion(df_actual)
            
            # El analyzer usa el snapshot_net.csv o snapshot_serv.csv automáticamente
            df_final = orchestrator.analyzer.generar_seguimiento(
                df_priorizado, 
                regulatorio, 
                os.getenv('PATH_ASSUMED')
            )
            
            st.success("Cruce completado.")
            st.dataframe(df_final)