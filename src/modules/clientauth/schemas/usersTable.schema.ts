import {
	pgTable,
	uuid,
	varchar,
	text,
	boolean,
	integer,
	timestamp,
	pgEnum,
	index,
	uniqueIndex,
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

// ─── Enums ────────────────────────────────────────────────────────────────────

export const userRoleEnum = pgEnum("user_role", [
	"admin",
	"moderator",
	"user",
]);

export const userStatusEnum = pgEnum("user_status", [
	"active",
	"inactive",
	"suspended",
	"pending",
	"deleted",
    "blacklisted"
]);

export const authProviderEnum = pgEnum("auth_provider", [
	"email",
	"google",
	"github",
	"facebook",
	"apple",
]);

// ─── Users Table ──────────────────────────────────────────────────────────────

export const users = pgTable(
	"users",
	{
		// ── Identity ──────────────────────────────────────────────────────────────
		id: uuid("id")
			.primaryKey()
			.default(sql`gen_random_uuid()`),

		email: varchar("email", { length: 255 }).notNull().unique(),

		username: varchar("username", { length: 50 }).unique(),

		// ── Auth ──────────────────────────────────────────────────────────────────
		passwordHash: varchar("password_hash", { length: 255 }),

		authProvider: authProviderEnum("auth_provider").notNull().default("email"),

		authProviderId: varchar("auth_provider_id", { length: 255 }),

		emailVerified: boolean("email_verified").notNull().default(false),

		// ── Profile ───────────────────────────────────────────────────────────────
		firstName: varchar("first_name", { length: 100 }),

		lastName: varchar("last_name", { length: 100 }),

		avatarUrl: text("avatar_url"),

		bio: text("bio"),

		phoneNumber: varchar("phone_number", { length: 20 }),

		dateOfBirth: timestamp("date_of_birth", { withTimezone: true }),

		// ── Access Control ────────────────────────────────────────────────────────
		role: userRoleEnum("role").notNull().default("user"),

		status: userStatusEnum("status").notNull().default("pending"),

		// ── Security & Session ────────────────────────────────────────────────────
		twoFactorEnabled: boolean("two_factor_enabled").notNull().default(false),

		twoFactorSecret: varchar("two_factor_secret", { length: 255 }),

		// bump this to invalidate ALL existing sessions for this user

		lastLoginAt: timestamp("last_login_at", { withTimezone: true }),

		lastLoginIp: varchar("last_login_ip", { length: 45 }), // IPv6-safe

		failedLoginAttempts: integer("failed_login_attempts").notNull().default(0),

		lockedUntil: timestamp("locked_until", { withTimezone: true }),

		// ── Soft Delete & Timestamps ──────────────────────────────────────────────
		deletedAt: timestamp("deleted_at", { withTimezone: true }),

		createdAt: timestamp("created_at", { withTimezone: true })
			.notNull()
			.default(sql`now()`),

		updatedAt: timestamp("updated_at", { withTimezone: true })
			.notNull()
			.default(sql`now()`),
	},

	// ── Indexes ─────────────────────────────────────────────────────────────────
	(table) => [
		uniqueIndex("users_email_idx").on(table.email),
		uniqueIndex("users_username_idx").on(table.username),
		index("users_status_idx").on(table.status),
		index("users_role_idx").on(table.role),
		index("users_auth_provider_idx").on(
			table.authProvider,
			table.authProviderId,
		),
		index("users_created_at_idx").on(table.createdAt),
	],
);

// ─── TypeScript Types ─────────────────────────────────────────────────────────

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
