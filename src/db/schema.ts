import {
    boolean,
    pgTable,
    text,
    timestamp,
    uuid,
    varchar,
} from "drizzle-orm/pg-core";

export const usersTable = pgTable("users", {
    id: uuid("id").primaryKey().defaultRandom(),

    firstName: varchar("first_name", { length: 25 }),
    lastName: varchar("last_name", { length: 25 }),

    profileImageUrl: text("profile_image_url"),

    email: varchar("email", { length: 322 }).notNull().unique(),
    emailVerified: boolean("email_verified").default(false).notNull(),

    password: varchar("password", { length: 66 }),
    salt: text("salt"),

    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").$onUpdate(() => new Date()),
});

export const applicationsTable = pgTable("applications", {
    id: uuid("id").primaryKey().defaultRandom(),

    displayName: varchar("display_name", { length: 50 }).notNull(),
    appUrl: text("url").notNull(),
    redirectUri: text("redirect_uri").notNull(),
    scopes: text("scopes").array().default(["openid", "profile", "email"]),
    grantTypes: text("grant_types")
        .array()
        .default(["authorization_code", "refresh_token"]),

    clientId: text("client_id").notNull().unique(),
    clientSecret: text("client_secret").notNull(),

    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").$onUpdate(() => new Date()),
});

export const authorizationCodesTable = pgTable("authorization_codes", {
    id: uuid("id").primaryKey().defaultRandom(),
    code: text("code").notNull().unique(),

    userId: uuid("user_id")
        .notNull()
        .references(() => usersTable.id, { onDelete: "cascade" }),
    applicationId: uuid("application_id")
        .notNull()
        .references(() => applicationsTable.id, { onDelete: "cascade" }),

    scopes: text("scopes").array().notNull(),
    nonce: text("nonce"),
    redirectUri: text("redirect_uri").notNull(),

    expiresAt: timestamp("expires_at").notNull(),
    consumedAt: timestamp("consumed_at"),

    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").$onUpdate(() => new Date()),
});
