import { config } from "../configs/app.config.js";
import crypto from "crypto";
import { AUTH_CONSTANTS } from "../constants.js";
import { NodemailerError } from "../types/errors.interface.js";

export function generateOTP() {
	return crypto.randomInt(100000, 999999).toString();
}

export function handleNodemailerError(err: Error): string {
	const error = err as NodemailerError;

	switch (error.code) {
		case "ECONNECTION":
		case "ETIMEDOUT":
			console.error("Network error - retry later:", error.message);
			throw new Error("Network error - please try again later");
			break;

		case "EAUTH":
			console.error("Authentication failed:", error.message);
			throw new Error("Authentication failed - please check credentials");
			break;

		case "EENVELOPE":
			console.error("Invalid recipients:", error.rejected);
			throw new Error("Invalid recipient email address");
			break;

		default:
			console.error("Send failed:", error.message, error);
			throw new Error("Failed to send email - please try again");
	}
}

// ─────────────────────────────────────────────
// 1. OTP VERIFICATION
// ─────────────────────────────────────────────
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
		case "verifyCurrentEmail":
		case "ve-em-cu":
			purposeDescription = "confirm your current email address before updating it.";
			actionText = "Confirm Email";
			purposeAbb = "ve-em-cu";
			break;
		case "updatePassword":
		case "up-pa":
			purposeDescription = "confirm your password change request.";
			actionText = "Confirm Change";
			purposeAbb = "up-pa";
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

// ─────────────────────────────────────────────
// 2. CONTACT US MESSAGES
// ─────────────────────────────────────────────
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
// 3. SESSIONS REVOKED
// reason: e.g. "suspicious activity detected", "password changed", "admin action"
// ─────────────────────────────────────────────
export function getSessionsRevokedEmail(params: {
  name: string;
  reason: string;
  revokedAt: string;
  ipAddress?: string;
  device?: string;
  loginUrl: string;
}): string {
  const { name, reason, revokedAt, ipAddress, device, loginUrl } = params;
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/><title>Sessions Signed Out</title></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f0f2f5;padding:40px 16px;">
  <tr><td align="center">
    <table role="presentation" width="100%" style="max-width:480px;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 4px 28px rgba(0,0,0,0.09);">

      <tr>
        <td style="background:linear-gradient(135deg,#1e1b4b,#4f46e5);padding:32px 40px;text-align:center;">
          <div style="display:inline-block;background:rgba(255,255,255,0.15);border-radius:50%;width:54px;height:54px;line-height:54px;font-size:26px;margin-bottom:12px;">🔐</div>
          <h1 style="margin:0;color:#fff;font-size:21px;font-weight:700;letter-spacing:0.4px;">All sessions signed out</h1>
          <p style="margin:6px 0 0;color:rgba(255,255,255,0.65);font-size:13px;">Security notification</p>
        </td>
      </tr>

      <tr><td style="padding:28px 40px 0;">
        <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, all your active sessions have been signed out.</p>
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Reason</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${reason}</p>
          </td></tr>
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Time</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${revokedAt}</p>
          </td></tr>
          ${ipAddress ? `<tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">IP Address</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${ipAddress}</p>
          </td></tr>` : ""}
          ${device ? `<tr><td style="padding:7px 0;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Device</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${device}</p>
          </td></tr>` : ""}
        </table>
      </td></tr>

      <tr><td style="padding:20px 40px 0;">
        <div style="background:#fff8f0;border:1px solid #fde8c8;border-radius:8px;padding:12px 16px;">
          <p style="margin:0;color:#92400e;font-size:13px;line-height:1.5;">⚠️ If this wasn't you, your account may be compromised. Change your password immediately.</p>
        </div>
      </td></tr>

      <tr><td style="padding:24px 40px 32px;text-align:center;">
        <a href="${loginUrl}" target="_blank" style="display:inline-block;background:linear-gradient(135deg,#7c3aed,#4f46e5);color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 30px;border-radius:8px;">Sign in again &rarr;</a>
      </td></tr>

      <tr><td style="background:#f8f9fb;border-top:1px solid #f0f0f0;padding:16px 40px;text-align:center;">
        <p style="margin:0;color:#9ca3af;font-size:12px;line-height:1.6;">This is an automated security notification. Do not reply to this email.</p>
      </td></tr>

    </table>
  </td></tr>
</table>
</body></html>`;
}


// ─────────────────────────────────────────────
// 4. PRIMARY EMAIL UPDATED
// ─────────────────────────────────────────────
export function getPrimaryEmailUpdatedEmail(params: {
  name: string;
  oldEmail: string;
  newEmail: string;
  updatedAt: string;
  revertUrl: string;
}): string {
  const { name, oldEmail, newEmail, updatedAt, revertUrl } = params;
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/><title>Primary Email Updated</title></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f0f2f5;padding:40px 16px;">
  <tr><td align="center">
    <table role="presentation" width="100%" style="max-width:480px;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 4px 28px rgba(0,0,0,0.09);">

      <tr>
        <td style="background:linear-gradient(135deg,#1a1a2e,#0f3460);padding:32px 40px;text-align:center;">
          <div style="display:inline-block;background:rgba(255,255,255,0.15);border-radius:50%;width:54px;height:54px;line-height:54px;font-size:26px;margin-bottom:12px;">✉️</div>
          <h1 style="margin:0;color:#fff;font-size:21px;font-weight:700;letter-spacing:0.4px;">Primary email updated</h1>
          <p style="margin:6px 0 0;color:rgba(255,255,255,0.65);font-size:13px;">Account security alert</p>
        </td>
      </tr>

      <tr><td style="padding:28px 40px 0;">
        <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, your primary email address has been updated.</p>
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Previous email</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${oldEmail}</p>
          </td></tr>
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">New email</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${newEmail}</p>
          </td></tr>
          <tr><td style="padding:7px 0;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Updated on</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${updatedAt}</p>
          </td></tr>
        </table>
      </td></tr>

      <tr><td style="padding:20px 40px 0;">
        <div style="background:#fff8f0;border:1px solid #fde8c8;border-radius:8px;padding:12px 16px;">
          <p style="margin:0;color:#92400e;font-size:13px;line-height:1.5;">⚠️ Didn't make this change? Revert it immediately using the button below.</p>
        </div>
      </td></tr>

      <tr><td style="padding:24px 40px 32px;text-align:center;">
        <a href="${revertUrl}" target="_blank" style="display:inline-block;background:linear-gradient(135deg,#0f3460,#1a1a8c);color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 30px;border-radius:8px;">Revert this change &rarr;</a>
      </td></tr>

      <tr><td style="background:#f8f9fb;border-top:1px solid #f0f0f0;padding:16px 40px;text-align:center;">
        <p style="margin:0;color:#9ca3af;font-size:12px;line-height:1.6;">This is an automated security notification. Do not reply to this email.</p>
      </td></tr>

    </table>
  </td></tr>
</table>
</body></html>`;
}


// ─────────────────────────────────────────────
// 5. TWO-FACTOR AUTHENTICATION UPDATED
// action: e.g. "enabled", "disabled", "changed to authenticator app"
// ─────────────────────────────────────────────
export function getTwoFactorUpdatedEmail(params: {
  name: string;
  action: string;
  updatedAt: string;
  device?: string;
  supportUrl: string;
}): string {
  const { name, action, updatedAt, device, supportUrl } = params;
  const isDisabled = action.toLowerCase().includes("disabled");
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/><title>Two-Factor Authentication ${action}</title></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f0f2f5;padding:40px 16px;">
  <tr><td align="center">
    <table role="presentation" width="100%" style="max-width:480px;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 4px 28px rgba(0,0,0,0.09);">

      <tr>
        <td style="background:${isDisabled ? "linear-gradient(135deg,#7f1d1d,#dc2626)" : "linear-gradient(135deg,#14532d,#16a34a)"};padding:32px 40px;text-align:center;">
          <div style="display:inline-block;background:rgba(255,255,255,0.15);border-radius:50%;width:54px;height:54px;line-height:54px;font-size:26px;margin-bottom:12px;">${isDisabled ? "🔓" : "🛡️"}</div>
          <h1 style="margin:0;color:#fff;font-size:21px;font-weight:700;letter-spacing:0.4px;">Two-factor authentication ${action}</h1>
          <p style="margin:6px 0 0;color:rgba(255,255,255,0.65);font-size:13px;">Account security update</p>
        </td>
      </tr>

      <tr><td style="padding:28px 40px 0;">
        <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, two-factor authentication on your account has been <strong>${action}</strong>.</p>
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Change</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">2FA ${action}</p>
          </td></tr>
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Time</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${updatedAt}</p>
          </td></tr>
          ${device ? `<tr><td style="padding:7px 0;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Device</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${device}</p>
          </td></tr>` : ""}
        </table>
      </td></tr>

      <tr><td style="padding:20px 40px 0;">
        ${isDisabled
          ? `<div style="background:#fff8f0;border:1px solid #fde8c8;border-radius:8px;padding:12px 16px;"><p style="margin:0;color:#92400e;font-size:13px;line-height:1.5;">⚠️ Disabling 2FA reduces your account security. If this wasn't you, contact support immediately.</p></div>`
          : `<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:12px 16px;"><p style="margin:0;color:#14532d;font-size:13px;line-height:1.5;">✅ Your account is now better protected with two-factor authentication.</p></div>`}
      </td></tr>

      <tr><td style="padding:24px 40px 32px;text-align:center;">
        <a href="${supportUrl}" target="_blank" style="display:inline-block;background:linear-gradient(135deg,#0f3460,#1a1a8c);color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 30px;border-radius:8px;">Contact support if this wasn't you &rarr;</a>
      </td></tr>

      <tr><td style="background:#f8f9fb;border-top:1px solid #f0f0f0;padding:16px 40px;text-align:center;">
        <p style="margin:0;color:#9ca3af;font-size:12px;line-height:1.6;">This is an automated security notification. Do not reply to this email.</p>
      </td></tr>

    </table>
  </td></tr>
</table>
</body></html>`;
}


// ─────────────────────────────────────────────
// 6. RECOVERY EMAIL UPDATED
// ─────────────────────────────────────────────
export function getRecoveryEmailUpdatedEmail(params: {
  name: string;
  oldRecoveryEmail: string;
  newRecoveryEmail: string;
  updatedAt: string;
  revertUrl: string;
}): string {
  const { name, oldRecoveryEmail, newRecoveryEmail, updatedAt, revertUrl } = params;
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/><title>Recovery Email Updated</title></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f0f2f5;padding:40px 16px;">
  <tr><td align="center">
    <table role="presentation" width="100%" style="max-width:480px;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 4px 28px rgba(0,0,0,0.09);">

      <tr>
        <td style="background:linear-gradient(135deg,#1a1a2e,#1e3a5f);padding:32px 40px;text-align:center;">
          <div style="display:inline-block;background:rgba(255,255,255,0.15);border-radius:50%;width:54px;height:54px;line-height:54px;font-size:26px;margin-bottom:12px;">📬</div>
          <h1 style="margin:0;color:#fff;font-size:21px;font-weight:700;letter-spacing:0.4px;">Recovery email updated</h1>
          <p style="margin:6px 0 0;color:rgba(255,255,255,0.65);font-size:13px;">Account security alert</p>
        </td>
      </tr>

      <tr><td style="padding:28px 40px 0;">
        <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, your account recovery email has been updated.</p>
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Previous recovery email</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${oldRecoveryEmail}</p>
          </td></tr>
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">New recovery email</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${newRecoveryEmail}</p>
          </td></tr>
          <tr><td style="padding:7px 0;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Updated on</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${updatedAt}</p>
          </td></tr>
        </table>
      </td></tr>

      <tr><td style="padding:20px 40px 0;">
        <div style="background:#fff8f0;border:1px solid #fde8c8;border-radius:8px;padding:12px 16px;">
          <p style="margin:0;color:#92400e;font-size:13px;line-height:1.5;">⚠️ If you didn't make this change, someone may have access to your account. Revert immediately.</p>
        </div>
      </td></tr>

      <tr><td style="padding:24px 40px 32px;text-align:center;">
        <a href="${revertUrl}" target="_blank" style="display:inline-block;background:linear-gradient(135deg,#0f3460,#1a1a8c);color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 30px;border-radius:8px;">Revert this change &rarr;</a>
      </td></tr>

      <tr><td style="background:#f8f9fb;border-top:1px solid #f0f0f0;padding:16px 40px;text-align:center;">
        <p style="margin:0;color:#9ca3af;font-size:12px;line-height:1.6;">This is an automated security notification. Do not reply to this email.</p>
      </td></tr>

    </table>
  </td></tr>
</table>
</body></html>`;
}


// ─────────────────────────────────────────────
// 7. ACCOUNT DELETION SCHEDULED
// ─────────────────────────────────────────────
export function getAccountDeletionEmail(params: {
  name: string;
  deletedAt: string;
  gracePeriodDays: number;
  recoverUrl: string;
}): string {
  const { name, deletedAt, gracePeriodDays, recoverUrl } = params;
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/><title>Account Deletion Scheduled</title></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f0f2f5;padding:40px 16px;">
  <tr><td align="center">
    <table role="presentation" width="100%" style="max-width:480px;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 4px 28px rgba(0,0,0,0.09);">

      <tr>
        <td style="background:linear-gradient(135deg,#450a0a,#991b1b);padding:32px 40px;text-align:center;">
          <div style="display:inline-block;background:rgba(255,255,255,0.15);border-radius:50%;width:54px;height:54px;line-height:54px;font-size:26px;margin-bottom:12px;">🗑️</div>
          <h1 style="margin:0;color:#fff;font-size:21px;font-weight:700;letter-spacing:0.4px;">Account deletion scheduled</h1>
          <p style="margin:6px 0 0;color:rgba(255,255,255,0.65);font-size:13px;">We're sorry to see you go</p>
        </td>
      </tr>

      <tr><td style="padding:28px 40px 0;">
        <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, your account has been scheduled for deletion.</p>
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Deletion requested</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${deletedAt}</p>
          </td></tr>
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Grace period</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${gracePeriodDays} days</p>
          </td></tr>
          <tr><td style="padding:7px 0;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Data wiped after</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">Grace period ends</p>
          </td></tr>
        </table>
      </td></tr>

      <tr><td style="padding:20px 40px 0;">
        <div style="background:#fff8f0;border:1px solid #fde8c8;border-radius:8px;padding:12px 16px;">
          <p style="margin:0;color:#92400e;font-size:13px;line-height:1.5;">⚠️ You have <strong>${gracePeriodDays} days</strong> to recover your account. After that, all data will be permanently deleted and cannot be restored.</p>
        </div>
      </td></tr>

      <tr><td style="padding:24px 40px 32px;text-align:center;">
        <a href="${recoverUrl}" target="_blank" style="display:inline-block;background:linear-gradient(135deg,#7c3aed,#db2777);color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 30px;border-radius:8px;">Recover my account &rarr;</a>
      </td></tr>

      <tr><td style="background:#f8f9fb;border-top:1px solid #f0f0f0;padding:16px 40px;text-align:center;">
        <p style="margin:0;color:#9ca3af;font-size:12px;line-height:1.6;">This is an automated security notification. Do not reply to this email.</p>
      </td></tr>

    </table>
  </td></tr>
</table>
</body></html>`;
}


// ─────────────────────────────────────────────
// 8. ACCOUNT RECOVERED
// ─────────────────────────────────────────────
export function getAccountRecoveredEmail(params: {
  name: string;
  recoveredAt: string;
  dashboardUrl: string;
}): string {
  const { name, recoveredAt, dashboardUrl } = params;
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/><title>Account Recovered</title></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f0f2f5;padding:40px 16px;">
  <tr><td align="center">
    <table role="presentation" width="100%" style="max-width:480px;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 4px 28px rgba(0,0,0,0.09);">

      <tr>
        <td style="background:linear-gradient(135deg,#14532d,#166534);padding:32px 40px;text-align:center;">
          <div style="display:inline-block;background:rgba(255,255,255,0.15);border-radius:50%;width:54px;height:54px;line-height:54px;font-size:26px;margin-bottom:12px;">🎉</div>
          <h1 style="margin:0;color:#fff;font-size:21px;font-weight:700;letter-spacing:0.4px;">Account recovered!</h1>
          <p style="margin:6px 0 0;color:rgba(255,255,255,0.65);font-size:13px;">Welcome back</p>
        </td>
      </tr>

      <tr><td style="padding:28px 40px 0;">
        <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Welcome back, <strong>${name}</strong>! Your account has been successfully recovered.</p>
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Recovered on</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${recoveredAt}</p>
          </td></tr>
          <tr><td style="padding:7px 0;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Status</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">Fully active</p>
          </td></tr>
        </table>
      </td></tr>

      <tr><td style="padding:20px 40px 0;">
        <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:12px 16px;">
          <p style="margin:0;color:#14532d;font-size:13px;line-height:1.5;">✅ All your data and settings have been restored. Your account is fully active again.</p>
        </div>
      </td></tr>

      <tr><td style="padding:24px 40px 32px;text-align:center;">
        <a href="${dashboardUrl}" target="_blank" style="display:inline-block;background:linear-gradient(135deg,#14532d,#16a34a);color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 30px;border-radius:8px;">Go to dashboard &rarr;</a>
      </td></tr>

      <tr><td style="background:#f8f9fb;border-top:1px solid #f0f0f0;padding:16px 40px;text-align:center;">
        <p style="margin:0;color:#9ca3af;font-size:12px;line-height:1.6;">This is an automated notification. Do not reply to this email.</p>
      </td></tr>

    </table>
  </td></tr>
</table>
</body></html>`;
}


// ─────────────────────────────────────────────
// 9. GENERIC ACCOUNT UPDATE SUCCESS
// Reuse for password, username, profile, notifications, etc.
// ─────────────────────────────────────────────
export function getAccountUpdateSuccessEmail(params: {
  name: string;
  updateType: string;   // e.g. "Password", "Username", "Profile photo"
  details?: string;
  updatedAt: string;
  dashboardUrl: string;
}): string {
  const { name, updateType, details, updatedAt, dashboardUrl } = params;
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/><title>${updateType} Updated</title></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f0f2f5;padding:40px 16px;">
  <tr><td align="center">
    <table role="presentation" width="100%" style="max-width:480px;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 4px 28px rgba(0,0,0,0.09);">

      <tr>
        <td style="background:linear-gradient(135deg,#1a1a2e,#0f3460);padding:32px 40px;text-align:center;">
          <div style="display:inline-block;background:rgba(255,255,255,0.15);border-radius:50%;width:54px;height:54px;line-height:54px;font-size:26px;margin-bottom:12px;">✅</div>
          <h1 style="margin:0;color:#fff;font-size:21px;font-weight:700;letter-spacing:0.4px;">${updateType} updated</h1>
          <p style="margin:6px 0 0;color:rgba(255,255,255,0.65);font-size:13px;">Account update confirmation</p>
        </td>
      </tr>

      <tr><td style="padding:28px 40px 0;">
        <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, your account has been updated successfully.</p>
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">What changed</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${updateType}</p>
          </td></tr>
          ${details ? `<tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Details</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${details}</p>
          </td></tr>` : ""}
          <tr><td style="padding:7px 0;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Updated on</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${updatedAt}</p>
          </td></tr>
        </table>
      </td></tr>

      <tr><td style="padding:20px 40px 0;">
        <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:12px 16px;">
          <p style="margin:0;color:#14532d;font-size:13px;line-height:1.5;">✅ Your changes have been saved and are now live on your account.</p>
        </div>
      </td></tr>

      <tr><td style="padding:24px 40px 32px;text-align:center;">
        <a href="${dashboardUrl}" target="_blank" style="display:inline-block;background:linear-gradient(135deg,#0f3460,#1a1a8c);color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 30px;border-radius:8px;">View account &rarr;</a>
      </td></tr>

      <tr><td style="background:#f8f9fb;border-top:1px solid #f0f0f0;padding:16px 40px;text-align:center;">
        <p style="margin:0;color:#9ca3af;font-size:12px;line-height:1.6;">This is an automated notification. Do not reply to this email.</p>
      </td></tr>

    </table>
  </td></tr>
</table>
</body></html>`;
}


// ─────────────────────────────────────────────
// 10. SUBSCRIPTION ACTIVATED
// plan: "free" | "basic" | "pro"
// ─────────────────────────────────────────────
export function getSubscriptionActivatedEmail(params: {
  name: string;
  plan: "free" | "basic" | "pro";
  activatedAt: string;
  expiresAt?: string;
  amount?: string;
  dashboardUrl: string;
}): string {
  const { name, plan, activatedAt, expiresAt, amount, dashboardUrl } = params;
  const planLabel = plan.charAt(0).toUpperCase() + plan.slice(1);
  const colors = { free: "linear-gradient(135deg,#374151,#6b7280)", basic: "linear-gradient(135deg,#1d4ed8,#3b82f6)", pro: "linear-gradient(135deg,#7c3aed,#a855f7)" };
  const icons  = { free: "🆓", basic: "⚡", pro: "👑" };
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/><title>${planLabel} Plan Activated</title></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f0f2f5;padding:40px 16px;">
  <tr><td align="center">
    <table role="presentation" width="100%" style="max-width:480px;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 4px 28px rgba(0,0,0,0.09);">

      <tr>
        <td style="background:${colors[plan]};padding:32px 40px;text-align:center;">
          <div style="display:inline-block;background:rgba(255,255,255,0.15);border-radius:50%;width:54px;height:54px;line-height:54px;font-size:26px;margin-bottom:12px;">${icons[plan]}</div>
          <h1 style="margin:0;color:#fff;font-size:21px;font-weight:700;letter-spacing:0.4px;">${planLabel} plan activated</h1>
          <p style="margin:6px 0 0;color:rgba(255,255,255,0.65);font-size:13px;">Subscription confirmation</p>
        </td>
      </tr>

      <tr><td style="padding:28px 40px 0;">
        <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, your <strong>${planLabel}</strong> plan is now active!</p>
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Plan</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${planLabel}</p>
          </td></tr>
          ${amount ? `<tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Amount paid</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${amount}</p>
          </td></tr>` : ""}
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Activated on</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${activatedAt}</p>
          </td></tr>
          <tr><td style="padding:7px 0;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Valid until</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${expiresAt ?? "Lifetime free"}</p>
          </td></tr>
        </table>
      </td></tr>

      <tr><td style="padding:20px 40px 0;">
        <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:12px 16px;">
          <p style="margin:0;color:#14532d;font-size:13px;line-height:1.5;">✅ You now have full access to all ${planLabel} features.</p>
        </div>
      </td></tr>

      <tr><td style="padding:24px 40px 32px;text-align:center;">
        <a href="${dashboardUrl}" target="_blank" style="display:inline-block;background:${colors[plan]};color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 30px;border-radius:8px;">Explore your plan &rarr;</a>
      </td></tr>

      <tr><td style="background:#f8f9fb;border-top:1px solid #f0f0f0;padding:16px 40px;text-align:center;">
        <p style="margin:0;color:#9ca3af;font-size:12px;line-height:1.6;">This is an automated notification. Do not reply to this email.</p>
      </td></tr>

    </table>
  </td></tr>
</table>
</body></html>`;
}


// ─────────────────────────────────────────────
// 11. SUBSCRIPTION EXPIRY REMINDER
// Send 3–5 days before expiry
// ─────────────────────────────────────────────
export function getSubscriptionExpiryReminderEmail(params: {
  name: string;
  plan: "basic" | "pro";
  expiresAt: string;
  daysLeft: number;
  renewUrl: string;
}): string {
  const { name, plan, expiresAt, daysLeft, renewUrl } = params;
  const planLabel = plan.charAt(0).toUpperCase() + plan.slice(1);
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/><title>Your ${planLabel} Plan Expires Soon</title></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f0f2f5;padding:40px 16px;">
  <tr><td align="center">
    <table role="presentation" width="100%" style="max-width:480px;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 4px 28px rgba(0,0,0,0.09);">

      <tr>
        <td style="background:linear-gradient(135deg,#78350f,#b45309);padding:32px 40px;text-align:center;">
          <div style="display:inline-block;background:rgba(255,255,255,0.15);border-radius:50%;width:54px;height:54px;line-height:54px;font-size:26px;margin-bottom:12px;">⏳</div>
          <h1 style="margin:0;color:#fff;font-size:21px;font-weight:700;letter-spacing:0.4px;">Your plan expires soon</h1>
          <p style="margin:6px 0 0;color:rgba(255,255,255,0.65);font-size:13px;">${daysLeft} day${daysLeft !== 1 ? "s" : ""} remaining</p>
        </td>
      </tr>

      <tr><td style="padding:28px 40px 0;">
        <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, your <strong>${planLabel}</strong> subscription is expiring soon.</p>
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Plan</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${planLabel}</p>
          </td></tr>
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Expires on</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${expiresAt}</p>
          </td></tr>
          <tr><td style="padding:7px 0;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Days remaining</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#ef4444;">${daysLeft} day${daysLeft !== 1 ? "s" : ""}</p>
          </td></tr>
        </table>
      </td></tr>

      <tr><td style="padding:20px 40px 0;">
        <div style="background:#fff8f0;border:1px solid #fde8c8;border-radius:8px;padding:12px 16px;">
          <p style="margin:0;color:#92400e;font-size:13px;line-height:1.5;">⚠️ Renew before <strong>${expiresAt}</strong> to avoid losing access to ${planLabel} features.</p>
        </div>
      </td></tr>

      <tr><td style="padding:24px 40px 32px;text-align:center;">
        <a href="${renewUrl}" target="_blank" style="display:inline-block;background:linear-gradient(135deg,#b45309,#d97706);color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 30px;border-radius:8px;">Renew now &rarr;</a>
      </td></tr>

      <tr><td style="background:#f8f9fb;border-top:1px solid #f0f0f0;padding:16px 40px;text-align:center;">
        <p style="margin:0;color:#9ca3af;font-size:12px;line-height:1.6;">This is an automated notification. Do not reply to this email.</p>
      </td></tr>

    </table>
  </td></tr>
</table>
</body></html>`;
}


// ─────────────────────────────────────────────
// 12. SUBSCRIPTION EXPIRED + DOWNGRADE NOTICE
// Send 2–3 days after expiry if not renewed
// ─────────────────────────────────────────────
export function getSubscriptionExpiredEmail(params: {
  name: string;
  plan: "basic" | "pro";
  expiredAt: string;
  renewUrl: string;
}): string {
  const { name, plan, expiredAt, renewUrl } = params;
  const planLabel = plan.charAt(0).toUpperCase() + plan.slice(1);
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/><title>Subscription Expired</title></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f0f2f5;padding:40px 16px;">
  <tr><td align="center">
    <table role="presentation" width="100%" style="max-width:480px;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 4px 28px rgba(0,0,0,0.09);">

      <tr>
        <td style="background:linear-gradient(135deg,#1f2937,#374151);padding:32px 40px;text-align:center;">
          <div style="display:inline-block;background:rgba(255,255,255,0.15);border-radius:50%;width:54px;height:54px;line-height:54px;font-size:26px;margin-bottom:12px;">📭</div>
          <h1 style="margin:0;color:#fff;font-size:21px;font-weight:700;letter-spacing:0.4px;">Subscription expired</h1>
          <p style="margin:6px 0 0;color:rgba(255,255,255,0.65);font-size:13px;">Your plan has ended</p>
        </td>
      </tr>

      <tr><td style="padding:28px 40px 0;">
        <p style="margin:0 0 16px;color:#374151;font-size:15px;line-height:1.7;">Hi <strong>${name}</strong>, your <strong>${planLabel}</strong> subscription has expired.</p>
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Plan</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${planLabel}</p>
          </td></tr>
          <tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Expired on</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">${expiredAt}</p>
          </td></tr>
          <tr><td style="padding:7px 0;">
            <span style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Current access</span>
            <p style="margin:3px 0 0;font-size:14px;font-weight:600;color:#1a1a2e;">Free plan</p>
          </td></tr>
        </table>
      </td></tr>

      <tr><td style="padding:20px 40px 0;">
        <div style="background:#fff8f0;border:1px solid #fde8c8;border-radius:8px;padding:12px 16px;">
          <p style="margin:0;color:#92400e;font-size:13px;line-height:1.5;">⚠️ You've been moved to the free plan. Renew to restore your ${planLabel} features.</p>
        </div>
      </td></tr>

      <tr><td style="padding:24px 40px 32px;text-align:center;">
        <a href="${renewUrl}" target="_blank" style="display:inline-block;background:linear-gradient(135deg,#7c3aed,#4f46e5);color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 30px;border-radius:8px;">Renew subscription &rarr;</a>
      </td></tr>

      <tr><td style="background:#f8f9fb;border-top:1px solid #f0f0f0;padding:16px 40px;text-align:center;">
        <p style="margin:0;color:#9ca3af;font-size:12px;line-height:1.6;">This is an automated notification. Do not reply to this email.</p>
      </td></tr>

    </table>
  </td></tr>
</table>
</body></html>`;
}
