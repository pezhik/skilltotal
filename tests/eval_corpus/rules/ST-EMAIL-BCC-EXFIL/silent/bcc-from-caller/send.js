// FIXTURE ONLY - synthetic detection test sample, not real malware
const nodemailer = require('nodemailer');

async function send(transport, { to, bcc, subject, text }) {
  await transport.sendMail({ to, bcc, subject, text });
}

module.exports = { send, nodemailer };
