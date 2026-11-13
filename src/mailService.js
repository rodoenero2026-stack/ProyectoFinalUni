const nodemailer = require('nodemailer');

// Historial en memoria de los últimos mensajes enviados (Correo / SMS) para inspección en el laboratorio
const sentMessagesHistory = [];

async function sendRecoveryCode({ toEmail, nombre, codigo, metodo }) {
  const timestamp = new Date().toLocaleString('es-MX');
  const subject = `[Seguridad en Cómputo] Código de Verificación y Recuperación (${codigo})`;
  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 20px; border: 1px solid #1e293b; border-radius: 10px; background: #0f172a; color: #f8fafc;">
      <h2 style="color: #38bdf8; margin-top: 0;">Seguridad en Cómputo - Verificación en 2 Pasos</h2>
      <p>Hola <strong>${nombre}</strong>,</p>
      <p>Se ha solicitado una operación de seguridad mediante <strong>${metodo}</strong>.</p>
      <div style="background: #1e293b; padding: 16px; border-radius: 8px; text-align: center; margin: 20px 0;">
        <span style="font-size: 28px; font-weight: bold; letter-spacing: 6px; color: #22c55e;">${codigo}</span>
      </div>
      <p style="font-size: 13px; color: #94a3b8;">Este código expira en 10 minutos. Si no solicitaste este código, ignora este mensaje.</p>
    </div>
  `;

  let smtpSent = false;
  let smtpInfo = 'Modo Laboratorio Local Activo (Bandeja Virtual)';

  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    try {
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });
      await transporter.sendMail({
        from: process.env.SMTP_FROM || `"Seguridad en Cómputo" <${process.env.SMTP_USER}>`,
        to: toEmail,
        subject,
        html: htmlContent
      });
      smtpSent = true;
      smtpInfo = `Enviado por SMTP (${process.env.SMTP_HOST})`;
    } catch (err) {
      smtpInfo = `Fallback a Bandeja Virtual (${err.message})`;
    }
  }

  const record = {
    id: sentMessagesHistory.length + 1,
    to: toEmail,
    nombre,
    codigo,
    metodo,
    subject,
    timestamp,
    smtpSent,
    smtpInfo
  };
  sentMessagesHistory.unshift(record);
  if (sentMessagesHistory.length > 30) sentMessagesHistory.pop();

  return record;
}

function getRecentMessages() {
  return sentMessagesHistory;
}

module.exports = {
  sendRecoveryCode,
  getRecentMessages
};
