const nodemailer = require("nodemailer");

async function sendEmail(to, subject, text, html) {
  const transporter = nodemailer.createTransport({
    host: "smtp-mail.outlook.com",
    port: 587,
    secure: false,
    auth: {
      user: "contact@shopbstreet.com",
      pass: "wmpbqxfttptmqjmj",
    },
  });

  const mailOptions = {
    from: "contact@shopbstreet.com",
    to,
    subject,
    text,
  };

  const info = await transporter.sendMail(mailOptions);
  return info;
}

module.exports = sendEmail;
