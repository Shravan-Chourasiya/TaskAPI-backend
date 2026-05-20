"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.userSchema = void 0;
var mongoose_1 = require("mongoose");
var crypto = require("crypto");
var bcrypt = require("bcryptjs");
exports.userSchema = new mongoose_1.default.Schema({
    username: {
        type: String,
        required: [true, "Username is required"],
        unique: true,
        trim: true,
        lowercase: true,
        minlength: [3, "Username must be at least 3 characters"],
        maxlength: [40, "Username cannot exceed 40 characters"],
        match: [
            /^[a-z0-9_-]+$/,
            "Username can only contain lowercase letters, numbers, hyphens, and underscores",
        ],
    },
    email: {
        type: String,
        required: [true, "Email is required"],
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^\S+@\S+\.\S+$/, "Invalid email format"],
        index: true,
    },
    passwordHash: {
        type: String,
        required: [true, "Password is required"],
        minlength: [8, "Password must be at least 8 characters"],
        select: false,
    },
    status: {
        type: String,
        enum: ["active", "unverified", "suspended", "deleted"],
        default: "unverified",
        index: true,
    },
    isVerified: {
        type: Boolean,
        default: false,
        index: true,
    },
    verifiedAt: Date,
    lastPassword: {
        type: String,
        select: false,
    },
    lastPasswordChangedAt: Date,
    failedLoginAttempts: {
        type: Number,
        default: 0,
        max: [10, "Too many failed login attempts"],
    },
    accountLockedUntil: Date,
    lastFailedLoginAt: Date,
    lastLoginAt: Date,
    loginCount: {
        type: Number,
        default: 0,
    },
    lastLoginDevice: {
        type: [
            {
                deviceIP: String,
                userAgent: String,
                deviceType: String,
                browser: String,
                os: String,
                deviceId: {
                    type: String,
                },
            },
        ],
        select: false,
        default: [],
    },
    activeSessions: {
        type: Number,
        default: 0,
        max: [5, "Cannot have more than 5 concurrent devices"],
    },
    lastActiveAt: {
        type: Date,
    },
    profile: {
        firstName: {
            type: String,
            trim: true,
            maxlength: [50, "First name cannot exceed 50 characters"],
        },
        lastName: {
            type: String,
            trim: true,
            maxlength: [50, "Last name cannot exceed 50 characters"],
        },
        avatarUrl: String,
        bio: {
            type: String,
            maxlength: [500, "Bio cannot exceed 500 characters"],
        },
        phone: {
            type: String,
            match: [/^\+?[1-9]\d{1,14}$/, "Invalid phone number format"],
        },
        phoneVerified: {
            type: Boolean,
            default: false,
        },
        country: {
            type: String,
            trim: true,
            maxlength: [100, "Country name cannot exceed 100 characters"],
        },
    },
    roles: {
        type: [String],
        enum: ["user", "admin", "moderator", "developer"],
        default: ["user"],
    },
    isDeleted: {
        type: Boolean,
        default: false,
        index: true,
    },
    deletedAt: Date,
    scheduledDeletionAt: {
        type: Date,
    },
    deletedBy: {
        type: mongoose_1.default.Schema.Types.ObjectId,
        ref: "Users",
    },
    is2FAEnabled: {
        type: Boolean,
        default: false,
        index: true,
    },
    twoFASecret: {
        type: String,
        select: false,
    },
    twoFA_Options: {
        type: [String],
        enum: ["email", "sms", "authenticator"],
        default: ["email"],
        select: false,
    },
    isBlackListed: {
        type: Boolean,
        default: false,
        index: true,
    },
    blackListReason: String,
    blackListedAt: Date,
}, {
    timestamps: true,
    collection: "users",
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
});
// Indexs for efficient querying
exports.userSchema.index({ email: 1, status: 1 });
exports.userSchema.index({ email: 1, isDeleted: 1 });
exports.userSchema.index({ email: 1, isVerified: 1 });
exports.userSchema.index({ email: 1, isBlackListed: 1 });
exports.userSchema.index({ email: 1, is2FAEnabled: 1 });
// TTL Index for permanent deletion of soft-deleted accounts
exports.userSchema.index({ scheduledDeletionAt: 1 }, {
    expireAfterSeconds: 0,
    partialFilterExpression: { isDeleted: true, status: "deleted" },
});
// virtual fields : Calculated after a db Call in ram Creates runtime fields using db existing fields
exports.userSchema.virtual("fullName").get(function () {
    var _a, _b;
    var first = ((_a = this.profile) === null || _a === void 0 ? void 0 : _a.firstName) || "";
    var last = ((_b = this.profile) === null || _b === void 0 ? void 0 : _b.lastName) || "";
    return "".concat(first, " ").concat(last).trim() || this.username;
});
exports.userSchema.virtual("isLocked").get(function () {
    return !!(this.accountLockedUntil && this.accountLockedUntil > new Date());
});
exports.userSchema.virtual("isActive").get(function () {
    return this.status === "active" && this.isVerified && !this.isDeleted;
});
exports.userSchema.virtual("accountAge").get(function () {
    var now = new Date();
    var created = this.createdAt || now;
    return Math.floor((now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24));
});
// ============ MIDDLEWARE ============
// Pre-save: Hash password if modified
exports.userSchema.pre("save", function () {
    return __awaiter(this, void 0, void 0, function () {
        var _a;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    // Skip if already hashed or not modified
                    if (!this.isModified("passwordHash") || this.passwordHash.startsWith("$2")) {
                        return [2 /*return*/];
                    }
                    _a = this;
                    return [4 /*yield*/, bcrypt.hash(this.passwordHash, 12)];
                case 1:
                    _a.passwordHash = _b.sent();
                    this.lastPasswordChangedAt = new Date();
                    return [2 /*return*/];
            }
        });
    });
});
// Pre-save: Update verification status
exports.userSchema.pre("save", function () {
    if (this.isModified("isVerified") && this.isVerified && !this.verifiedAt) {
        this.verifiedAt = new Date();
        this.status = "active";
    }
});
// Pre-save: Set scheduled deletion date
exports.userSchema.pre("save", function () {
    if (this.isModified("isDeleted") &&
        this.isDeleted &&
        !this.scheduledDeletionAt) {
        this.deletedAt = new Date();
        this.scheduledDeletionAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
        this.status = "deleted";
    }
});
// ============ INSTANCE METHODS ============
// Compare password
exports.userSchema.methods.comparePassword = function (candidatePassword) {
    return __awaiter(this, void 0, void 0, function () {
        var result;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, bcrypt.compare(candidatePassword, this.passwordHash)];
                case 1:
                    result = _a.sent();
                    return [2 /*return*/, result];
            }
        });
    });
};
// Check if password was used before
exports.userSchema.methods.isPasswordReused = function (newPassword) {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            if (!this.lastPassword) {
                return [2 /*return*/, false];
            }
            return [2 /*return*/, bcrypt.compare(newPassword, this.lastPassword)];
        });
    });
};
// Increment failed login attempts
exports.userSchema.methods.incrementFailedLogin = function () {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    this.failedLoginAttempts += 1;
                    this.lastFailedLoginAt = new Date();
                    // Lock account after 5 failed attempts for 15 minutes
                    if (this.failedLoginAttempts >= 5) {
                        this.accountLockedUntil = new Date(Date.now() + 15 * 60 * 1000);
                    }
                    // Lock account for 1 hour after 10 attempts
                    if (this.failedLoginAttempts >= 10) {
                        this.accountLockedUntil = new Date(Date.now() + 60 * 60 * 1000);
                    }
                    // Suspend account after 15 attempts
                    if (this.failedLoginAttempts >= 15) {
                        this.status = "suspended";
                        this.accountLockedUntil = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
                    }
                    return [4 /*yield*/, this.save()];
                case 1:
                    _a.sent();
                    return [2 /*return*/];
            }
        });
    });
};
// Reset failed login attempts
exports.userSchema.methods.resetFailedLogin = function () {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    this.failedLoginAttempts = 0;
                    this.accountLockedUntil = undefined;
                    this.lastFailedLoginAt = undefined;
                    return [4 /*yield*/, this.save()];
                case 1:
                    _a.sent();
                    return [2 /*return*/];
            }
        });
    });
};
// Update login activity
exports.userSchema.methods.updateLoginActivity = function (ip, userAgent) {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    this.lastLoginAt = new Date();
                    this.lastActiveAt = new Date();
                    this.loginCount += 1;
                    this.activeSessions += 1;
                    if (!this.lastLoginDevice) {
                        this.lastLoginDevice = [];
                    }
                    // Parse user agent (basic implementation)
                    this.lastLoginDevice.push({
                        userAgent: userAgent,
                        deviceType: /mobile/i.test(userAgent) ? "mobile" : "desktop",
                        browser: userAgent.split("/")[0] || "unknown",
                        os: /windows/i.test(userAgent)
                            ? "Windows"
                            : /mac/i.test(userAgent)
                                ? "macOS"
                                : /linux/i.test(userAgent)
                                    ? "Linux"
                                    : "unknown",
                        deviceId: crypto.randomBytes(16).toString("hex"),
                    });
                    return [4 /*yield*/, this.save()];
                case 1:
                    _a.sent();
                    return [2 /*return*/];
            }
        });
    });
};
// Soft delete account
exports.userSchema.methods.softDelete = function (deletedBy) {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    this.isDeleted = true;
                    this.deletedAt = new Date();
                    this.status = "deleted";
                    this.scheduledDeletionAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
                    if (deletedBy) {
                        this.deletedBy = deletedBy;
                    }
                    return [4 /*yield*/, this.save()];
                case 1:
                    _a.sent();
                    return [2 /*return*/];
            }
        });
    });
};
// Restore deleted account
exports.userSchema.methods.restore = function () {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    this.isDeleted = false;
                    this.deletedAt = undefined;
                    this.scheduledDeletionAt = undefined;
                    this.deletedBy = undefined;
                    this.status = this.isVerified ? "active" : "unverified";
                    return [4 /*yield*/, this.save()];
                case 1:
                    _a.sent();
                    return [2 /*return*/];
            }
        });
    });
};
// Generate verification token
exports.userSchema.methods.generateVerificationToken = function () {
    var token = crypto.randomBytes(32).toString("hex");
    this.verificationToken = crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
    this.verificationTokenExpiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    return token;
};
// ============ STATIC METHODS FOR ADMIN USE =============
// Find active users
exports.userSchema.statics.findActive = function () {
    return this.find({ status: "active", isDeleted: false });
};
// Find by email (case-insensitive)
exports.userSchema.statics.findByEmail = function (email) {
    return this.findOne({ email: email.toLowerCase(), isDeleted: false });
};
// Find by username (case-insensitive)
exports.userSchema.statics.findByUsername = function (username) {
    return this.findOne({ username: username.toLowerCase(), isDeleted: false });
};
// Find users by role
exports.userSchema.statics.findByRole = function (role) {
    return this.find({ roles: role, isDeleted: false });
};
// Get user statistics
exports.userSchema.statics.getStatistics = function () {
    return __awaiter(this, void 0, void 0, function () {
        var _a, total, active, unverified, suspended, deleted;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: return [4 /*yield*/, Promise.all([
                        this.countDocuments({ isDeleted: false }),
                        this.countDocuments({ status: "active", isDeleted: false }),
                        this.countDocuments({ status: "unverified", isDeleted: false }),
                        this.countDocuments({ status: "suspended", isDeleted: false }),
                        this.countDocuments({ isDeleted: true }),
                    ])];
                case 1:
                    _a = _b.sent(), total = _a[0], active = _a[1], unverified = _a[2], suspended = _a[3], deleted = _a[4];
                    return [2 /*return*/, { total: total, active: active, unverified: unverified, suspended: suspended, deleted: deleted }];
            }
        });
    });
};
var userModel = mongoose_1.default.model("Users", exports.userSchema);
exports.default = userModel;
