import express from "express";
import "dotenv/config";
import path from "node:path";
import jose from "node-jose"
import JWT from "jsonwebtoken";
import { PRIVATE_KEY, PUBLIC_KEY } from "./utils/cert.js";


const app = express();
const PORT = process.env.PORT ?? 7000;

app.use(express.json());
app.use(express.urlencoded());
app.use(express.static(path.resolve("public")));

app.get("/", (req, res) =>
    res.json({ message: "Still Alive, Still Breathing" }),
);

app.get("/health", (req, res) => {
    return res.json({ message: `Server is healthy`, healthy: true });
});

app.get("/.well-known/openid-configuration", (req, res) => {
    const ISSUER = `http://localhost:${PORT}`;

    return res.json({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/o/authenticate`,
        token_endpoint: `${ISSUER}/o/token`,
        userinfo_endpoint: `${ISSUER}/o/userinfo`,
        jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    });
});

app.get("/.well-known/jwks.json", async(_, res) => {
    const key = await jose.JWK.asKey(PUBLIC_KEY, "pem");
    return res.json({keys: [key.toJSON()]})
})

app.listen(PORT, () => {
    console.log(`OIDC Service is runnng on http://localhost:${PORT}`);
});
