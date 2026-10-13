import { createApp } from "./app.js";
import { DEV_JWT_SECRET, loadConfig } from "./config.js";

const config = loadConfig();
if (config.jwtSecret === DEV_JWT_SECRET) {
  console.warn("WARNING: using the built-in DEV JWT secret. Set JWT_SECRET for anything real.");
}

const port = Number(process.env.PORT ?? 3000);
const server = createApp({ config }).listen(port, () => {
  console.log(`auth-service listening on http://localhost:${port}`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
