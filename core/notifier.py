import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

class Notifier:
    def __init__(self):
        load_dotenv()
        self.enabled = os.getenv('ENABLE_EMAIL', 'False').lower() == 'true'
        self.smtp_server = os.getenv('SMTP_SERVER')
        self.smtp_port = int(os.getenv('SMTP_PORT', 25))
        self.sender = os.getenv('EMAIL_FROM')
        self.receiver = os.getenv('EMAIL_TO')

    def enviar_reporte(self, subject, body, adjuntos=None):
        """
        Envía el correo electrónico si el flag ENABLE_EMAIL está en True.
        """
        if not self.enabled:
            print("[AVISO] Envío de correo desactivado en el .env. Saltando paso.")
            return

        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = self.sender
        msg['To'] = self.receiver
        msg.set_content(body)

        # Agregar archivos adjuntos (Sábana, PDF, HTML)
        if adjuntos:
            for ruta in adjuntos:
                if os.path.exists(ruta):
                    with open(ruta, 'rb') as f:
                        file_data = f.read()
                        file_name = os.path.basename(ruta)
                    msg.add_attachment(
                        file_data, 
                        maintype='application', 
                        subtype='octet-stream', 
                        filename=file_name
                    )

        try:
            # Conexión al Relay On-Premises (usualmente sin autenticación explícita)
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.send_message(msg)
            print(f"[ÉXITO] Reporte enviado correctamente a {self.receiver}")
        except Exception as e:
            print(f"[ERROR] No se pudo enviar el correo: {e}")