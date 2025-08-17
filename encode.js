const fs = require("fs");

// Read your service account JSON file
const serviceAccount = fs.readFileSync("firebase_service-account.json", "utf8");

// Convert to Base64
const base64 = Buffer.from(serviceAccount).toString("base64");

// Print it (copy this for your .env)
console.log(base64);
