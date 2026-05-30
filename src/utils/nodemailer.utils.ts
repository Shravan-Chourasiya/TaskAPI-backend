import { config } from "../configs/app.config.js";
import crypto from "crypto";
import { AUTH_CONSTANTS } from "../constants.js";

export function generateOTP() {
	return crypto.randomInt(100000, 999999).toString();
}

export function getOtpHTML(otp: string, purpose: string) {
	let purposeDescription, actionText, purposeAbb;
	switch (purpose) {
		case "verifyEmailOR":
			purposeDescription = "verify your email address.";
			actionText = "Verify Email";
			purposeAbb = "ve-em-or";
			break;
		case "verifyEmailUP":
			purposeDescription = "verify your email address and update it .";
			actionText = "Verify Email";
			purposeAbb = "ve-em-up";
			break;
		case "resetPassword":
			purposeDescription = "reset your password.";
			actionText = "Reset Password";
			purposeAbb = "re-pa";
			break;
		case "accountRecovery":
			purposeDescription = "recover your account.";
			actionText = "Recover Account";
			purposeAbb = "ac-re";
			break;
		case "resendOtp":
			purposeDescription = "New OTP for your previous request.";
			actionText = "Resend OTP";
			purposeAbb = "re-otp";
			break;
	}

	return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Your OTP Code</title>
</head>
<body style="margin:0; padding:0; background-color:#f4f6f9; font-family: 'Segoe UI', Helvetica, Arial, sans-serif;">

  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#f4f6f9; padding: 40px 16px;">
    <tr>
      <td align="center">

        <!-- Card -->
        <table role="presentation" width="100%" style="max-width:440px; background:#ffffff; border-radius:12px; overflow:hidden; box-shadow: 0 4px 24px rgba(0,0,0,0.08);">

          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 60%, #0f3460 100%); padding: 36px 40px; text-align:center;">
              <div style="display:inline-block; background:rgba(255,255,255,0.1); border-radius:50%; width:56px; height:56px; line-height:56px; font-size:26px; margin-bottom:14px;">🔐</div>
              <h1 style="margin:0; color:#ffffff; font-size:22px; font-weight:700; letter-spacing:0.5px;">Verification Code</h1>
              <p style="margin:6px 0 0; color:rgba(255,255,255,0.65); font-size:14px;">Use the code below to continue</p>
            </td>
          </tr>

          <!-- OTP Block -->
          <tr>
            <td style="padding: 36px 40px 20px; text-align:center;">
              <p style="margin:0 0 8px; color:#6b7280; font-size:13px; text-transform:uppercase; letter-spacing:1.5px; font-weight:600;">Your one-time password</p>
              <div style="display:inline-block; background:#f8faff; border:2px dashed #c7d7fd; border-radius:10px; padding:18px 32px; margin:8px 0;">
                <span style="font-size:36px; font-weight:800; letter-spacing:10px; color:#1a1a2e; font-family:'Courier New', monospace;">${otp}</span>
              </div>
              <p style="margin:14px 0 0; color:#9ca3af; font-size:13px;">⏱ Expires in <strong style="color:#ef4444;">${AUTH_CONSTANTS.OTP_EXPIRY_MINUTES} minutes</strong></p>
            </td>
          </tr>

          <!-- Divider -->
          <tr>
            <td style="padding: 0 40px;">
              <hr style="border:none; border-top:1px solid #f0f0f0; margin:0;" />
            </td>
          </tr>

          <!-- Action -->
          <tr>
            <td style="padding: 24px 40px; text-align:center;">
              <p style="margin:0 0 20px; color:#4b5563; font-size:14px; line-height:1.6;">
                Click the button below to <strong style="color:#1a1a2e;">${purposeDescription}</strong>.
              </p>
              <a href="${config.BASE_URL}/verify?purpose=${purposeAbb}" target="_blank"
                style="display:inline-block; background: linear-gradient(135deg, #0f3460, #1a1a8c); color:#ffffff; text-decoration:none; font-size:15px; font-weight:600; padding:13px 32px; border-radius:8px; letter-spacing:0.3px;">
                ${actionText} &rarr;
              </a>
            </td>
          </tr>

          <!-- Warning -->
          <tr>
            <td style="padding: 0 40px 32px; text-align:center;">
              <div style="background:#fff8f0; border:1px solid #fde8c8; border-radius:8px; padding:12px 16px;">
                <p style="margin:0; color:#92400e; font-size:13px; line-height:1.5;">
                  🔒 <strong>Never share this code.</strong> If you didn't request this, you can safely ignore this email.
                </p>
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f9fafb; border-top:1px solid #f0f0f0; padding:18px 40px; text-align:center; border-radius:0 0 12px 12px;">
              <p style="margin:0; color:#9ca3af; font-size:12px; line-height:1.6;">
                This is an automated message. Please do not reply to this email.
              </p>
            </td>
          </tr>

        </table>
        <!-- /Card -->

      </td>
    </tr>
  </table>

</body>
</html>
`;
}

export const getContactUsHTML = (
	name: string,
	email: string,
	message: string,
) => {
	return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>New Contact Message</title>
</head>
<body style="margin:0; padding:0; background-color:#f4f6f9; font-family: 'Segoe UI', Helvetica, Arial, sans-serif;">

  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#f4f6f9; padding: 40px 16px;">
    <tr>
      <td align="center">

        <!-- Card -->
        <table role="presentation" width="100%" style="max-width:520px; background:#ffffff; border-radius:12px; overflow:hidden; box-shadow: 0 4px 24px rgba(0,0,0,0.08);">

          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 60%, #0f3460 100%); padding: 32px 40px; text-align:center;">
              <div style="display:inline-block; background:rgba(255,255,255,0.1); border-radius:50%; width:52px; height:52px; line-height:52px; font-size:24px; margin-bottom:12px;">📬</div>
              <h1 style="margin:0; color:#ffffff; font-size:20px; font-weight:700; letter-spacing:0.5px;">New Contact Message</h1>
              <p style="margin:6px 0 0; color:rgba(255,255,255,0.6); font-size:13px;">Someone reached out via your website</p>
            </td>
          </tr>

          <!-- Sender Info -->
          <tr>
            <td style="padding: 28px 40px 0;">
              <p style="margin:0 0 12px; color:#6b7280; font-size:12px; text-transform:uppercase; letter-spacing:1.5px; font-weight:600;">Sender Details</p>

              <!-- Name Row -->
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-bottom:10px;">
                <tr>
                  <td style="width:36px; vertical-align:middle;">
                    <div style="background:#f0f4ff; border-radius:8px; width:34px; height:34px; text-align:center; line-height:34px; font-size:16px;">👤</div>
                  </td>
                  <td style="padding-left:12px; vertical-align:middle;">
                    <p style="margin:0; font-size:11px; color:#9ca3af; text-transform:uppercase; letter-spacing:0.8px;">Name</p>
                    <p style="margin:2px 0 0; font-size:15px; font-weight:600; color:#1a1a2e;">${name}</p>
                  </td>
                </tr>
              </table>

              <!-- Email Row -->
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-bottom:10px;">
                <tr>
                  <td style="width:36px; vertical-align:middle;">
                    <div style="background:#f0f4ff; border-radius:8px; width:34px; height:34px; text-align:center; line-height:34px; font-size:16px;">✉️</div>
                  </td>
                  <td style="padding-left:12px; vertical-align:middle;">
                    <p style="margin:0; font-size:11px; color:#9ca3af; text-transform:uppercase; letter-spacing:0.8px;">Email</p>
                    <a href="mailto:${email}" style="display:block; margin:2px 0 0; font-size:15px; font-weight:600; color:#0f3460; text-decoration:none;">${email}</a>
                  </td>
                </tr>
              </table>

            </td>
          </tr>

          <!-- Divider -->
          <tr>
            <td style="padding: 20px 40px 0;">
              <hr style="border:none; border-top:1px solid #f0f0f0; margin:0;" />
            </td>
          </tr>

          <!-- Message Body -->
          <tr>
            <td style="padding: 24px 40px;">
              <p style="margin:0 0 12px; color:#6b7280; font-size:12px; text-transform:uppercase; letter-spacing:1.5px; font-weight:600;">Message</p>
              <div style="background:#f8faff; border-left:4px solid #0f3460; border-radius:0 8px 8px 0; padding:16px 20px;">
                <p style="margin:0; color:#374151; font-size:15px; line-height:1.8; white-space:pre-wrap;">${message}</p>
              </div>
            </td>
          </tr>

          <!-- Reply CTA -->
          <tr>
            <td style="padding: 0 40px 32px; text-align:center;">
              <a href="mailto:${email}?subject=Re: Your message&body=Hi ${name},%0D%0A%0D%0A"
                style="display:inline-block; background: linear-gradient(135deg, #0f3460, #1a1a8c); color:#ffffff; text-decoration:none; font-size:14px; font-weight:600; padding:12px 28px; border-radius:8px; letter-spacing:0.3px;">
                Reply to ${name} &rarr;
              </a>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f9fafb; border-top:1px solid #f0f0f0; padding:16px 40px; text-align:center; border-radius:0 0 12px 12px;">
              <p style="margin:0; color:#9ca3af; font-size:12px; line-height:1.6;">
                This notification was triggered from the Contact Us form on your website.
              </p>
            </td>
          </tr>

        </table>
        <!-- /Card -->

      </td>
    </tr>
  </table>

</body>
</html>
`;
};
// ─────────────────────────────────────────────
// SHARED HELPERS
// ─────────────────────────────────────────────

const baseStyles = `
  body { margin:0; padding:0; background-color:#f0f2f5; font-family:'Segoe UI',Helvetica,Arial,sans-serif; }
`;

function shell(
	headerColor: string,
	icon: string,
	title: string,
	subtitle: string,
	body: string,
): string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>${title}</title>
  <style>${baseStyles}</style>
</head>
<body>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f0f2f5;padding:40px 16px;">
  <tr><td align="center">
    <table role="presentation" width="100%" style="max-width:480px;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 4px 28px rgba(0,0,0,0.09);">

      <!-- Header -->
      <tr>
        <td style="background:${headerColor};padding:32px 40px;text-align:center;">
          <div style="display:inline-block;background:rgba(255,255,255,0.15);border-radius:50%;width:54px;height:54px;line-height:54px;font-size:26px;margin-bottom:12px;">${icon}</div>
          <h1 style="margin:0;color:#ffffff;font-size:21px;font-weight:700;letter-spacing:0.4px;">${title}</h1>
          <p style="margin:6px 0 0;color:rgba(255,255,255,0.65);font-size:13px;">${subtitle}</p>
        </td>
      </tr>

      <!-- Body -->
      ${body}

      <!-- Footer -->
      <tr>
        <td style="background:#f8f9fb;border-top:1px solid #f0f0f0;padding:16px 40px;text-align:center;border-radius:0 0 14px 14px;">
          <p style="margin:0;color:#9ca3af;font-size:12px;line-height:1.6;">This is an automated security notification. Do not reply to this email.</p>
        </td>
      </tr>

    </table>
  </td></tr>
</table>
</body>
</html>`;
}

function infoRow(label: string, value: string): string {
	return `
  <tr>
    <td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
      <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">${label}</span>
      <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${value}</p>
    </td>
  </tr>`;
}

function ctaButton(
	href: string,
	text: string,
	color = "linear-gradient(135deg,#0f3460,#1a1a8c)",
): string {
	return `<a href="${href}" target="_blank" style="display:inline-block;background:${color};color:#ffffff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 30px;border-radius:8px;letter-spacing:0.3px;">${text} &rarr;</a>`;
}

function warningBox(text: string): string {
	return `<div style="background:#fff8f0;border:1px solid #fde8c8;border-radius:8px;padding:12px 16px;margin-top:8px;">
    <p style="margin:0;color:#92400e;font-size:13px;line-height:1.5;">⚠️ ${text}</p>
  </div>`;
}

function successBadge(text: string): string {
	return `<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:12px 16px;margin-top:8px;">
    <p style="margin:0;color:#14532d;font-size:13px;line-height:1.5;">✅ ${text}</p>
  </div>`;
}

function detailsBlock(rows: string): string {
	return `<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-top:4px;">
    ${rows}
  </table>`;
}

// ─────────────────────────────────────────────
// 1. SESSIONS REVOKED
// Dynamic reason passed in — e.g. "suspicious login detected", "password changed", "admin action"
// ─────────────────────────────────────────────
export function sessionsRevokedEmail(params: {
	name: string;
	reason: string; // e.g. "suspicious activity detected from an unknown device"
	revokedAt: string; // e.g. "June 3, 2025 at 10:42 AM UTC"
	ipAddress?: string;
	device?: string;
	loginUrl: string;
}): string {
	const { name, reason, revokedAt, ipAddress, device, loginUrl } = params;
	const body = `
  <tr><td style="padding:28px 40px 0;">
    <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, all your active sessions have been signed out.</p>
    ${detailsBlock(`
      ${infoRow("Reason", reason)}
      ${infoRow("Time", revokedAt)}
      ${ipAddress ? infoRow("IP Address", ipAddress) : ""}
      ${device ? infoRow("Device", device) : ""}
    `)}
  </td></tr>
  <tr><td style="padding:20px 40px 0;">${warningBox("If this wasn't you, your account may be compromised. Change your password immediately.")}</td></tr>
  <tr><td style="padding:24px 40px 32px;text-align:center;">${ctaButton(loginUrl, "Sign in again", "linear-gradient(135deg,#7c3aed,#4f46e5)")}</td></tr>`;

	return shell(
		"linear-gradient(135deg,#1e1b4b,#4f46e5)",
		"🔐",
		"All sessions signed out",
		"Security notification",
		body,
	);
}

// ─────────────────────────────────────────────
// 2. PRIMARY EMAIL UPDATED
// ─────────────────────────────────────────────
export function primaryEmailUpdatedEmail(params: {
	name: string;
	oldEmail: string;
	newEmail: string;
	updatedAt: string;
	revertUrl: string;
}): string {
	const { name, oldEmail, newEmail, updatedAt, revertUrl } = params;
	const body = `
  <tr><td style="padding:28px 40px 0;">
    <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, your primary email address has been updated.</p>
    ${detailsBlock(`
      ${infoRow("Previous email", oldEmail)}
      ${infoRow("New email", newEmail)}
      ${infoRow("Updated on", updatedAt)}
    `)}
  </td></tr>
  <tr><td style="padding:20px 40px 0;">${warningBox("Didn't make this change? Revert it immediately using the button below.")}</td></tr>
  <tr><td style="padding:24px 40px 32px;text-align:center;">${ctaButton(revertUrl, "Revert this change")}</td></tr>`;

	return shell(
		"linear-gradient(135deg,#1a1a2e,#0f3460)",
		"✉️",
		"Primary email updated",
		"Account security alert",
		body,
	);
}

// ─────────────────────────────────────────────
// 3. TWO-FACTOR AUTHENTICATION UPDATED
// action: "enabled" | "disabled" | "method changed"
// ─────────────────────────────────────────────
export function twoFactorUpdatedEmail(params: {
	name: string;
	action: string; // e.g. "enabled", "disabled", "changed to authenticator app"
	updatedAt: string;
	device?: string;
	supportUrl: string;
}): string {
	const { name, action, updatedAt, device, supportUrl } = params;
	const isDisabled = action.toLowerCase().includes("disabled");
	const body = `
  <tr><td style="padding:28px 40px 0;">
    <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, two-factor authentication on your account has been <strong>${action}</strong>.</p>
    ${detailsBlock(`
      ${infoRow("Change", `2FA ${action}`)}
      ${infoRow("Time", updatedAt)}
      ${device ? infoRow("Device", device) : ""}
    `)}
  </td></tr>
  <tr><td style="padding:20px 40px 0;">
    ${
			isDisabled
				? warningBox(
						"Disabling 2FA reduces your account security. If this wasn't you, contact support immediately.",
					)
				: successBadge(
						"Your account is now better protected with two-factor authentication.",
					)
		}
  </td></tr>
  <tr><td style="padding:24px 40px 32px;text-align:center;">${ctaButton(supportUrl, "Contact support if this wasn't you")}</td></tr>`;

	return shell(
		isDisabled
			? "linear-gradient(135deg,#7f1d1d,#dc2626)"
			: "linear-gradient(135deg,#14532d,#16a34a)",
		isDisabled ? "🔓" : "🛡️",
		`Two-factor authentication ${action}`,
		"Account security update",
		body,
	);
}

// ─────────────────────────────────────────────
// 4. RECOVERY EMAIL UPDATED
// ─────────────────────────────────────────────
export function recoveryEmailUpdatedEmail(params: {
	name: string;
	oldRecoveryEmail: string;
	newRecoveryEmail: string;
	updatedAt: string;
	revertUrl: string;
}): string {
	const { name, oldRecoveryEmail, newRecoveryEmail, updatedAt, revertUrl } =
		params;
	const body = `
  <tr><td style="padding:28px 40px 0;">
    <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, your account recovery email has been updated.</p>
    ${detailsBlock(`
      ${infoRow("Previous recovery email", oldRecoveryEmail)}
      ${infoRow("New recovery email", newRecoveryEmail)}
      ${infoRow("Updated on", updatedAt)}
    `)}
  </td></tr>
  <tr><td style="padding:20px 40px 0;">${warningBox("If you didn't make this change, someone may have access to your account. Revert immediately.")}</td></tr>
  <tr><td style="padding:24px 40px 32px;text-align:center;">${ctaButton(revertUrl, "Revert this change")}</td></tr>`;

	return shell(
		"linear-gradient(135deg,#1a1a2e,#1e3a5f)",
		"📬",
		"Recovery email updated",
		"Account security alert",
		body,
	);
}

// ─────────────────────────────────────────────
// 5. ACCOUNT DELETION CONFIRMATION
// ─────────────────────────────────────────────
export function accountDeletionEmail(params: {
	name: string;
	deletedAt: string;
	gracePeriodDays: number; // how many days until permanently gone
	recoverUrl: string;
}): string {
	const { name, deletedAt, gracePeriodDays, recoverUrl } = params;
	const body = `
  <tr><td style="padding:28px 40px 0;">
    <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, your account has been scheduled for deletion.</p>
    ${detailsBlock(`
      ${infoRow("Deletion requested", deletedAt)}
      ${infoRow("Permanent deletion in", `${gracePeriodDays} days`)}
      ${infoRow("Data wiped after", `Grace period ends`)}
    `)}
  </td></tr>
  <tr><td style="padding:20px 40px 0;">${warningBox(`You have ${gracePeriodDays} days to recover your account. After that, all data will be permanently deleted and cannot be restored.`)}</td></tr>
  <tr><td style="padding:24px 40px 32px;text-align:center;">${ctaButton(recoverUrl, "Recover my account", "linear-gradient(135deg,#7c3aed,#db2777)")}</td></tr>`;

	return shell(
		"linear-gradient(135deg,#450a0a,#991b1b)",
		"🗑️",
		"Account deletion scheduled",
		"We're sorry to see you go",
		body,
	);
}

// ─────────────────────────────────────────────
// 6. DELETED ACCOUNT RECOVERED
// ─────────────────────────────────────────────
export function accountRecoveredEmail(params: {
	name: string;
	recoveredAt: string;
	dashboardUrl: string;
}): string {
	const { name, recoveredAt, dashboardUrl } = params;
	const body = `
  <tr><td style="padding:28px 40px 0;">
    <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Welcome back, <strong>${name}</strong>! Your account has been successfully recovered.</p>
    ${detailsBlock(`
      ${infoRow("Recovered on", recoveredAt)}
      ${infoRow("Status", "Fully active")}
    `)}
  </td></tr>
  <tr><td style="padding:20px 40px 0;">${successBadge("All your data and settings have been restored. Your account is fully active again.")}</td></tr>
  <tr><td style="padding:24px 40px 32px;text-align:center;">${ctaButton(dashboardUrl, "Go to dashboard", "linear-gradient(135deg,#14532d,#16a34a)")}</td></tr>`;

	return shell(
		"linear-gradient(135deg,#14532d,#166534)",
		"🎉",
		"Account recovered!",
		"Welcome back",
		body,
	);
}

// ─────────────────────────────────────────────
// 7. GENERIC ACCOUNT UPDATE SUCCESS
// Reusable for any settings change: password, username, profile, notifications, etc.
// ─────────────────────────────────────────────
export function accountUpdateSuccessEmail(params: {
	name: string;
	updateType: string; // e.g. "Password", "Profile photo", "Username", "Notification preferences"
	details?: string; // optional extra context shown below the update type
	updatedAt: string;
	dashboardUrl: string;
}): string {
	const { name, updateType, details, updatedAt, dashboardUrl } = params;
	const body = `
  <tr><td style="padding:28px 40px 0;">
    <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, your account has been updated successfully.</p>
    ${detailsBlock(`
      ${infoRow("What changed", updateType)}
      ${details ? infoRow("Details", details) : ""}
      ${infoRow("Updated on", updatedAt)}
    `)}
  </td></tr>
  <tr><td style="padding:20px 40px 0;">${successBadge("Your changes have been saved and are now live on your account.")}</td></tr>
  <tr><td style="padding:24px 40px 32px;text-align:center;">${ctaButton(dashboardUrl, "View account")}</td></tr>`;

	return shell(
		"linear-gradient(135deg,#1a1a2e,#0f3460)",
		"✅",
		`${updateType} updated`,
		"Account update confirmation",
		body,
	);
}

// ─────────────────────────────────────────────
// 8. SUBSCRIPTION ACTIVATED
// plan: "free" | "basic" | "pro"
// ─────────────────────────────────────────────
export function subscriptionActivatedEmail(params: {
	name: string;
	plan: "free" | "basic" | "pro";
	activatedAt: string;
	expiresAt?: string; // undefined for free plan
	amount?: string; // e.g. "₹499" — undefined for free
	dashboardUrl: string;
}): string {
	const { name, plan, activatedAt, expiresAt, amount, dashboardUrl } = params;

	const planColors: Record<string, string> = {
		free: "linear-gradient(135deg,#374151,#6b7280)",
		basic: "linear-gradient(135deg,#1d4ed8,#3b82f6)",
		pro: "linear-gradient(135deg,#7c3aed,#a855f7)",
	};
	const planIcons: Record<string, string> = {
		free: "🆓",
		basic: "⚡",
		pro: "👑",
	};

	const body = `
  <tr><td style="padding:28px 40px 0;">
    <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, your <strong>${plan.charAt(0).toUpperCase() + plan.slice(1)}</strong> plan is now active!</p>
    ${detailsBlock(`
      ${infoRow("Plan", plan.charAt(0).toUpperCase() + plan.slice(1))}
      ${amount ? infoRow("Amount paid", amount) : ""}
      ${infoRow("Activated on", activatedAt)}
      ${expiresAt ? infoRow("Valid until", expiresAt) : infoRow("Duration", "Lifetime free")}
    `)}
  </td></tr>
  <tr><td style="padding:20px 40px 0;">${successBadge(`You now have full access to all ${plan} features.`)}</td></tr>
  <tr><td style="padding:24px 40px 32px;text-align:center;">${ctaButton(dashboardUrl, "Explore your plan", planColors[plan])}</td></tr>`;

	return shell(
		planColors[plan] as string,
		planIcons[plan] as string,
		`${plan.charAt(0).toUpperCase() + plan.slice(1)} plan activated`,
		"Subscription confirmation",
		body,
	);
}

// ─────────────────────────────────────────────
// 9. SUBSCRIPTION EXPIRY REMINDER (tenure ending soon)
// Send this 3–5 days before expiry
// ─────────────────────────────────────────────
export function subscriptionExpiryReminderEmail(params: {
	name: string;
	plan: "basic" | "pro";
	expiresAt: string; // e.g. "June 10, 2025"
	daysLeft: number; // e.g. 3
	renewUrl: string;
}): string {
	const { name, plan, expiresAt, daysLeft, renewUrl } = params;
	const body = `
  <tr><td style="padding:28px 40px 0;">
    <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, your <strong>${plan.charAt(0).toUpperCase() + plan.slice(1)}</strong> subscription is expiring soon.</p>
    ${detailsBlock(`
      ${infoRow("Plan", plan.charAt(0).toUpperCase() + plan.slice(1))}
      ${infoRow("Expires on", expiresAt)}
      ${infoRow("Days remaining", `${daysLeft} day${daysLeft !== 1 ? "s" : ""}`)}
    `)}
  </td></tr>
  <tr><td style="padding:20px 40px 0;">${warningBox(`Renew before ${expiresAt} to avoid losing access to ${plan} features.`)}</td></tr>
  <tr><td style="padding:24px 40px 32px;text-align:center;">${ctaButton(renewUrl, "Renew now", "linear-gradient(135deg,#b45309,#d97706)")}</td></tr>`;

	return shell(
		"linear-gradient(135deg,#78350f,#b45309)",
		"⏳",
		"Your plan expires soon",
		`${daysLeft} day${daysLeft !== 1 ? "s" : ""} remaining`,
		body,
	);
}

// ─────────────────────────────────────────────
// 10. SUBSCRIPTION EXPIRED + DOWNGRADE NOTICE
// Send 2–3 days after expiry if not renewed
// ─────────────────────────────────────────────
export function subscriptionExpiredEmail(params: {
	name: string;
	plan: "basic" | "pro";
	expiredAt: string;
	renewUrl: string;
}): string {
	const { name, plan, expiredAt, renewUrl } = params;
	const body = `
  <tr><td style="padding:28px 40px 0;">
    <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, your <strong>${plan.charAt(0).toUpperCase() + plan.slice(1)}</strong> subscription has expired.</p>
    ${detailsBlock(`
      ${infoRow("Plan", plan.charAt(0).toUpperCase() + plan.slice(1))}
      ${infoRow("Expired on", expiredAt)}
      ${infoRow("Current access", "Free plan")}
    `)}
  </td></tr>
  <tr><td style="padding:20px 40px 0;">${warningBox(`You've been moved to the free plan. Renew to restore your ${plan} features.`)}</td></tr>
  <tr><td style="padding:20px 40px 32px;text-align:center;">${ctaButton(renewUrl, "Renew subscription", "linear-gradient(135deg,#7c3aed,#4f46e5)")}</td></tr>`;

	return shell(
		"linear-gradient(135deg,#1f2937,#374151)",
		"📭",
		"Subscription expired",
		"Your plan has ended",
		body,
	);
}
