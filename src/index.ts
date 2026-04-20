import express from "express";
import "dotenv/config";
import path from "node:path";
import jose from "node-jose";
import JWT from "jsonwebtoken";
import { PRIVATE_KEY, PUBLIC_KEY } from "./utils/cert.js";
import { db } from "./db/index.js";
import { usersTable } from "./db/schema.js";
import { eq } from "drizzle-orm";
import crypto from "node:crypto";
import { JWTClaims } from "./utils/user-token.js";

const app = express();
const PORT = process.env.PORT ?? 7000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.resolve("public")));

app.get("/", (req, res) =>
    res.json({
        message: "Still Alive, Still Breathing",
        wellknown: `http://localhost:${PORT}/.well-known/openid-configuration`,
    }),
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

app.get("/.well-known/jwks.json", async (_, res) => {
    const key = await jose.JWK.asKey(PUBLIC_KEY, "pem");
    return res.json({ keys: [key.toJSON()] });
});

app.get("/o/authenticate", (req, res) => {
    return res.sendFile(path.resolve("public", "authenticate.html"));
});

app.post("/o/authenticate/sign-in", async (req, res) => {
    console.log(req.body);

    const { email, password } = req.body;

    if (!email || !password) {
        return res
            .status(400)
            .json({ message: "Email or Password is required" });
    }

    const [user] = await db
        .select()
        .from(usersTable)
        .where(eq(usersTable.email, email))
        .limit(1);

    if (!user || !user.password || !user.salt) {
        return res.status(400).json({ message: "Invalid email or password." });
    }

    const hash = crypto
        .createHash("sha256")
        .update(password + user.salt)
        .digest("hex");

    if (hash !== user.password) {
        return res.status(401).json({ message: "Invalid email or password" });
    }

    const ISSUER = `http://localhost:${PORT}`;
    const now = Math.floor(Date.now() / 1000);

    const claims: JWTClaims = {
        iss: ISSUER,
        sub: user.id,
        email: user.email,
        email_verified: String(user.emailVerified),
        exp: now + 3600,
        given_name: user.firstName ?? "",
        family_name: user.lastName ?? undefined,
        name: [user.firstName, user.lastName].filter(Boolean).join(" "),
        picture: user.profileImageUrl ?? undefined,
    };

    const token = JWT.sign(claims, PRIVATE_KEY, { algorithm: "RS256" });

    return res.json({ token });
});

app.post("/o/authenticate/sign-up", async (req, res) => {
    const { firstName, lastName, email, password } = req.body;
    if (!email || !password || !firstName) {
        res.status(400).json({
            message: "First name, email, and password are required.",
        });
        return;
    }

    const [existing] = await db
        .select()
        .from(usersTable)
        .where(eq(usersTable.email, email))
        .limit(1);

    if (existing) {
        res.status(409).json({
            message: "An account with this email already exists.",
        });
        return;
    }

    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto
        .createHash("sha256")
        .update(password + salt)
        .digest("hex");

    await db.insert(usersTable).values({
        firstName,
        lastName: lastName ?? null,
        email,
        password: hash,
        salt,
    });

    return res.status(201).json({ ok: true });
});

app.post("/o/userinfo", async (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith("Bearer ")) {
        res.status(401).json({
            message: "Missing or invalid Authorization header.",
        });
        return;
    }

    const token = authHeader.slice(7);

    let claims: JWTClaims;
    try {
        claims = JWT.verify(token, PUBLIC_KEY, {
            algorithms: ["RS256"],
        }) as JWTClaims;
    } catch {
        res.status(401).json({ message: "Invalid or expired token." });
        return;
    }

    const [user] = await db
        .select()
        .from(usersTable)
        .where(eq(usersTable.id, claims.sub))
        .limit(1);

    if (!user) {
        res.status(404).json({ message: "User not found." });
        return;
    }

    res.json({
        sub: user.id,
        email: user.email,
        email_verified: user.emailVerified,
        given_name: user.firstName,
        family_name: user.lastName,
        name: [user.firstName, user.lastName].filter(Boolean).join(" "),
        picture: user.profileImageUrl,
    });
});

app.listen(PORT, () => {
    console.log(`OIDC Service is runnng on http://localhost:${PORT}`);
});
