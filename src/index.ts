import express from "express";
import "dotenv/config";
import path from "node:path";
import jose from "node-jose";
import JWT from "jsonwebtoken";
import { PRIVATE_KEY, PUBLIC_KEY } from "./utils/cert.js";
import { db } from "./db/index.js";
import {
    applicationsTable,
    authorizationCodesTable,
    usersTable,
} from "./db/schema.js";
import { and, eq, isNull } from "drizzle-orm";
import crypto, { randomBytes } from "node:crypto";
import { BaseClaims, JWTClaims } from "./utils/user-token.js";
import session from "express-session";

const app = express();
const PORT = process.env.PORT ?? 7000;
const DEBUG_CLIENT_SECRETS = new Map<string, string>();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.resolve("public")));
app.use(
    session({
        secret: process.env.SESSION_SECRET!,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
        },
    }),
);

function normalizeToStringArray(value: unknown): string[] | undefined {
    if (Array.isArray(value)) {
        const normalized = value
            .map((entry) => String(entry).trim())
            .filter(Boolean);
        return normalized.length ? normalized : undefined;
    }

    if (typeof value === "string") {
        const normalized = value
            .split(/[\s,]+/)
            .map((entry) => entry.trim())
            .filter(Boolean);
        return normalized.length ? normalized : undefined;
    }

    return undefined;
}

function normalizeScopeToText(value: unknown): string | undefined {
    const normalized = normalizeToStringArray(value);
    if (normalized) {
        return normalized.join(" ");
    }

    if (typeof value === "string") {
        const trimmed = value.trim();
        return trimmed ? trimmed : undefined;
    }

    return undefined;
}
app.get("/", (req, res) =>
    res.json({
        message: "Still Alive, Still Breathing",
        WayneEnterprises: `http://localhost:${PORT}/o/authenticate?client_id=861ed1da-0e79-46ec-a0ea-e27f3151f16d&redirect_uri=https://batman.fandom.com/wiki/Wayne_Enterprises`,
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
        token_endpoint: `${ISSUER}/o/tokeninfo`,
        userinfo_endpoint: `${ISSUER}/o/userinfo`,
        jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    });
});

app.post("/o/tokeninfo", async (req, res) => {
    const {
        grant_type,
        code,
        client_id,
        client_secret,
        redirect_uri,
        refresh_token,
    } = req.body;

    if (grant_type === "authorization_code") {
        if (!code || !client_id || !client_secret || !redirect_uri) {
            return res.status(400).json({
                error: "invalid_request",
                error_description:
                    "code, client_id, client_secret and redirect_uri are required.",
            });
        }

        const [appRecord] = await db
            .select()
            .from(applicationsTable)
            .where(eq(applicationsTable.clientId, client_id))
            .limit(1);

        if (!appRecord) {
            return res.status(401).json({
                error: "invalid_client",
                error_description: "Client authentication failed.",
            });
        }

        const secretHash = crypto
            .createHash("sha256")
            .update(client_secret)
            .digest("hex");

        if (secretHash !== appRecord.clientSecret) {
            return res.status(401).json({
                error: "invalid_client",
                error_description: "Client authentication failed.",
            });
        }

        const [auth] = await db
            .select()
            .from(authorizationCodesTable)
            .where(eq(authorizationCodesTable.code, code))
            .limit(1);

        if (
            !auth ||
            new Date(auth.expiresAt).getTime() < Date.now() ||
            auth.consumedAt !== null
        ) {
            return res.status(400).json({
                error: "invalid_grant",
                error_description: "Authorization code is invalid or expired.",
            });
        }

        if (
            auth.applicationId !== appRecord.id ||
            auth.redirectUri !== redirect_uri ||
            appRecord.redirectUri !== redirect_uri
        ) {
            return res.status(400).json({
                error: "invalid_grant",
                error_description:
                    "Authorization code was not issued for this client or redirect_uri.",
            });
        }

        const consumeResult = await db
            .update(authorizationCodesTable)
            .set({ consumedAt: new Date() })
            .where(
                and(
                    eq(authorizationCodesTable.id, auth.id),
                    isNull(authorizationCodesTable.consumedAt),
                ),
            )
            .returning({ id: authorizationCodesTable.id });

        if (!consumeResult.length) {
            return res.status(400).json({
                error: "invalid_grant",
                error_description:
                    "Authorization code has already been consumed.",
            });
        }

        const [user] = await db
            .select()
            .from(usersTable)
            .where(eq(usersTable.id, auth.userId))
            .limit(1);

        if (!user) {
            return res.status(400).json({
                error: "invalid_grant",
                error_description: "User not found for authorization code.",
            });
        }

        const ISSUER = `http://localhost:${PORT}`;
        const now = Math.floor(Date.now() / 1000);

        const baseClaims: BaseClaims = {
            iss: ISSUER,
            sub: user.id,
            iat: now,
            client_id: appRecord.clientId,
            scope: auth.scopes.join(" "),
        };

        const accessClaims = {
            ...baseClaims,
            type: "access" as const,
            exp: now + 15 * 60,
            ...(auth.scopes.includes("email") && {
                email: user.email,
                email_verified: String(user.emailVerified),
            }),
            ...(auth.scopes.includes("profile") && {
                given_name: user.firstName ?? "",
                family_name: user.lastName ?? "",
                name: [user.firstName, user.lastName].filter(Boolean).join(" "),
                picture: user.profileImageUrl ?? undefined,
            }),
        };

        const accessToken = JWT.sign(accessClaims, PRIVATE_KEY, {
            algorithm: "RS256",
        });

        const refreshClaims = {
            ...baseClaims,
            type: "refresh" as const,
            exp: now + 7 * 24 * 60 * 60,
        };

        const refreshToken = JWT.sign(refreshClaims, PRIVATE_KEY, {
            algorithm: "RS256",
        });

        return res.json({
            access_token: accessToken,
            refresh_token: refreshToken,
            token_type: "Bearer",
            expires_in: 15 * 60,
            scope: auth.scopes.join(" "),
        });
    }

    if (grant_type === "refresh_token") {
        if (!refresh_token || !client_id || !client_secret) {
            return res.status(400).json({
                error: "invalid_request",
                error_description:
                    "refresh_token, client_id and client_secret are required.",
            });
        }

        const [appRecord] = await db
            .select()
            .from(applicationsTable)
            .where(eq(applicationsTable.clientId, client_id))
            .limit(1);

        if (!appRecord) {
            return res.status(401).json({
                error: "invalid_client",
                error_description: "Client authentication failed.",
            });
        }

        const secretHash = crypto
            .createHash("sha256")
            .update(client_secret)
            .digest("hex");

        if (secretHash !== appRecord.clientSecret) {
            return res.status(401).json({
                error: "invalid_client",
                error_description: "Client authentication failed.",
            });
        }

        let refreshClaims: JWTClaims;
        try {
            refreshClaims = JWT.verify(refresh_token, PUBLIC_KEY, {
                algorithms: ["RS256"],
            }) as JWTClaims;
        } catch {
            return res.status(400).json({
                error: "invalid_grant",
                error_description: "Refresh token is invalid or expired.",
            });
        }

        if (
            refreshClaims.type !== "refresh" ||
            refreshClaims.client_id !== client_id
        ) {
            return res.status(400).json({
                error: "invalid_grant",
                error_description:
                    "Refresh token is not valid for this client.",
            });
        }

        const [user] = await db
            .select()
            .from(usersTable)
            .where(eq(usersTable.id, refreshClaims.sub))
            .limit(1);

        if (!user) {
            return res.status(400).json({
                error: "invalid_grant",
                error_description: "User not found for refresh token.",
            });
        }

        const ISSUER = `http://localhost:${PORT}`;
        const now = Math.floor(Date.now() / 1000);
        const scopes = refreshClaims.scope
            ? refreshClaims.scope.split(/\s+/).filter(Boolean)
            : (appRecord.scopes ?? ["openid"]);

        const accessClaims = {
            iss: ISSUER,
            sub: user.id,
            iat: now,
            client_id: appRecord.clientId,
            scope: scopes.join(" "),
            type: "access" as const,
            exp: now + 15 * 60,
            ...(scopes.includes("email") && {
                email: user.email,
                email_verified: String(user.emailVerified),
            }),
            ...(scopes.includes("profile") && {
                given_name: user.firstName ?? "",
                family_name: user.lastName ?? "",
                name: [user.firstName, user.lastName].filter(Boolean).join(" "),
                picture: user.profileImageUrl ?? undefined,
            }),
        };

        const accessToken = JWT.sign(accessClaims, PRIVATE_KEY, {
            algorithm: "RS256",
        });

        return res.json({
            access_token: accessToken,
            token_type: "Bearer",
            expires_in: 15 * 60,
            scope: scopes.join(" "),
        });
    }

    return res.status(400).json({
        error: "unsupported_grant_type",
        error_description:
            "Only authorization_code and refresh_token grant_type are supported.",
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
    const { email, password, client_id, redirect_uri, state } = req.body;

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

    const [app] = await db
        .select()
        .from(applicationsTable)
        .where(eq(applicationsTable.clientId, client_id))
        .limit(1);

    if (!app || !app.clientSecret) {
        return res.status(400).json({ message: "Invalid email or password." });
    }

    const hash = crypto
        .createHash("sha256")
        .update(password + user.salt)
        .digest("hex");

    if (hash !== user.password) {
        return res.status(401).json({ message: "Invalid email or password" });
    }

    const nextState =
        typeof state === "string" && state.trim()
            ? state
            : crypto.randomBytes(8).toString("hex");
    req.session.userId = user.id;
    req.session.oauthState = nextState;
    await new Promise<void>((resolve, reject) => {
        req.session.save((err) => {
            if (err) {
                reject(err);
                return;
            }

            resolve();
        });
    });
    return res.json({
        redirect: `/consent.html?client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent(redirect_uri)}&state=${encodeURIComponent(nextState)}`,
    });
});

app.post("/o/consent", async (req, res) => {
    const {
        client_id,
        redirect_uri,
        state,
        scope,
        action,
        error,
        error_description,
    } = req.body;

    if (!client_id || !redirect_uri) {
        return res.status(400).json({
            success: false,
            message: "client_id and redirect_uri are required.",
        });
    }

    const [appRecord] = await db
        .select()
        .from(applicationsTable)
        .where(eq(applicationsTable.clientId, client_id))
        .limit(1);

    if (!appRecord || appRecord.redirectUri !== redirect_uri) {
        return res.status(400).json({
            success: false,
            message: "Invalid client or redirect URI.",
        });
    }

    if (error) {
        return res.status(400).json({
            success: false,
            redirect: `${redirect_uri}?error=access_denied&error_description=${encodeURIComponent(error_description || "The user did not consent.")}${state ? `&state=${encodeURIComponent(String(state))}` : ""}`,
        });
    }

    if (action !== "allow") {
        return res.status(400).json({
            success: false,
            message: "Unsupported consent action.",
        });
    }

    const userId = req.session.userId;

    if (!userId) {
        return res.status(401).json({
            success: false,
            message: "User session not found.",
        });
    }

    const normalizedScopes = normalizeToStringArray(scope) ??
        appRecord.scopes ?? ["openid"];

    const code = crypto.randomBytes(16).toString("hex");

    await db.insert(authorizationCodesTable).values({
        code,
        userId,
        applicationId: appRecord.id,
        scopes: normalizedScopes,
        nonce: null,
        redirectUri: redirect_uri,
        expiresAt: new Date(Date.now() + 1000 * 60),
    });

    //send redirect as a response to redirect from concent page
    return res.status(200).json({
        success: true,
        redirect: `${redirect_uri}?code=${encodeURIComponent(code)}${state ? `&state=${encodeURIComponent(String(state))}` : ""}`,
    });
});

app.get("/auth/callback", async (req, res) => {
    const code = typeof req.query.code === "string" ? req.query.code : "";
    const state = typeof req.query.state === "string" ? req.query.state : "";
    const expectedState = req.session.oauthState;

    if (!code) {
        return res.status(400).json({
            ok: false,
            message: "Authorization code is required.",
        });
    }

    if (!state || !expectedState || state !== expectedState) {
        return res.status(400).json({
            ok: false,
            message: "Invalid state parameter.",
        });
    }

    req.session.oauthState = undefined;
    await new Promise<void>((resolve, reject) => {
        req.session.save((err) => {
            if (err) {
                reject(err);
                return;
            }
            resolve();
        });
    });

    const [auth] = await db
        .select()
        .from(authorizationCodesTable)
        .where(eq(authorizationCodesTable.code, code))
        .limit(1);

    const [app] = await db
        .select()
        .from(applicationsTable)
        .where(eq(applicationsTable.id, auth.applicationId))
        .limit(1);

    if (!app) {
        return res.status(400).json({
            ok: false,
            message: "Application not found for authorization code.",
        });
    }

    const debugClientSecret = DEBUG_CLIENT_SECRETS.get(app.clientId);
    if (!debugClientSecret) {
        return res.status(400).json({
            ok: false,
            message:
                "No debug client secret found. Use the /admin/apps/new response client_secret with POST /o/tokeninfo manually.",
        });
    }

    let tokenResponse: unknown = null;
    try {
        const exchange = await fetch(`http://localhost:${PORT}/o/tokeninfo`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                grant_type: "authorization_code",
                code,
                client_id: app.clientId,
                client_secret: debugClientSecret,
                redirect_uri: app.redirectUri,
            }),
        });

        tokenResponse = await exchange.json().catch(() => null);
    } catch (error) {
        return res.status(500).json({
            ok: false,
            message:
                error instanceof Error
                    ? error.message
                    : "Token exchange failed.",
        });
    }

    return res.status(200).json({
        ok: true,
        code,
        state,
        tokenResponse,
    });
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

// ======================== ADMIN ROUTES ======================

app.get("/admin/apps", (req, res) => {
    return res.sendFile(path.resolve("public", "application.html"));
});

app.post("/admin/apps/new", async (req, res) => {
    const { displayName, appUrl, redirectUri, scopes, scope, grantTypes } =
        req.body;
    if (!displayName || !appUrl || !redirectUri) {
        res.status(400).json({
            message:
                "Display Name, Application URL and Redirect URL are required.",
        });
        return;
    }

    const [existing] = await db
        .select()
        .from(applicationsTable)
        .where(eq(applicationsTable.redirectUri, redirectUri))
        .limit(1);

    if (existing) {
        res.status(409).json({
            message: "An Application with this redirect uri already exists.",
        });
        return;
    }
    const clientId = crypto.randomUUID();
    const rawSecret = crypto.randomBytes(32).toString("hex");
    const clientSecret = crypto
        .createHash("sha256")
        .update(rawSecret)
        .digest("hex");

    const values: {
        displayName: string;
        appUrl: string;
        redirectUri: string;
        clientId: string;
        clientSecret: string;
        scopes?: string[];
        grantTypes?: string[];
    } = {
        displayName,
        appUrl,
        redirectUri,
        clientId,
        clientSecret,
    };

    const normalizedScopes = normalizeToStringArray(scopes ?? scope);
    const normalizedGrantTypes = normalizeToStringArray(grantTypes);

    if (normalizedScopes) {
        values.scopes = normalizedScopes;
    }
    if (normalizedGrantTypes) {
        values.grantTypes = normalizedGrantTypes;
    }

    await db.insert(applicationsTable).values(values);

    // Debug-only helper: keeps fresh client secrets in memory for local callback token exchange.
    // In production, the client app should store and use its own secret out-of-band.
    DEBUG_CLIENT_SECRETS.set(clientId, rawSecret);

    return res.status(201).json({
        message: "Application Created",
        client_id: clientId,
        client_secret: rawSecret,
        live_link: `http://localhost:${PORT}/o/authenticate?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}`,
    });
});

app.get("/admin/apps/registered", async (req, res) => {
    const { displayName } = req.body;

    const [company] = await db
        .select()
        .from(applicationsTable)
        .where(eq(applicationsTable.displayName, displayName))
        .limit(1);
    return res.status(200).json({
        live_link: `http://localhost:${PORT}/o/authenticate?client_id=${company.clientId}&redirect_uri=${company.redirectUri}`,
    });
});

app.post("/admin/apps/appname", async (req, res) => {
    const { client_id } = req.body;

    if (!client_id)
        return res.status(400).json({ message: "No client id received" });
    const [app] = await db
        .select()
        .from(applicationsTable)
        .where(eq(applicationsTable.clientId, client_id))
        .limit(1);

    if (!app || !app.clientSecret) {
        return res.status(400).json({ message: "Invalid email or password." });
    }

    return res.status(200).json({
        displayName: app.displayName,
        scopes: app.scopes,
        grantTypes: app.grantTypes,
    });
});
app.listen(PORT, () => {
    console.log(`OIDC Service is runnng on http://localhost:${PORT}`);
});
