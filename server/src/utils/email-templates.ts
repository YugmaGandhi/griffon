type OrgInvitationEmailParams = {
  email: string;
  invitationUrl: string;
  orgName: string;
  invitedByEmail: string;
  role: string;
  appName?: string;
};

export function orgInvitationEmailTemplate(params: OrgInvitationEmailParams): {
  subject: string;
  html: string;
  text: string;
} {
  const {
    email,
    invitationUrl,
    orgName,
    invitedByEmail,
    role,
    appName = 'Griffon',
  } = params;

  return {
    subject: `You've been invited to ${orgName} — ${appName}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #1A1A2E;">You've been invited to ${orgName}</h2>
        <p>Hi ${email},</p>
        <p>${invitedByEmail} has invited you to join <strong>${orgName}</strong> as a <strong>${role}</strong> on ${appName}.</p>
        <a href="${invitationUrl}"
           style="display: inline-block; background: #4F8EF7; color: white;
                  padding: 12px 24px; border-radius: 6px; text-decoration: none;
                  font-weight: bold; margin: 16px 0;">
          Accept Invitation
        </a>
        <p style="color: #6B7280; font-size: 14px;">
          This invitation expires in 7 days. If you don't have an account, you'll need to register first.
        </p>
        <p style="color: #6B7280; font-size: 12px;">
          Or copy this link: ${invitationUrl}
        </p>
      </div>
    `,
    text: `You've been invited to ${orgName} on ${appName}.\n\n${invitedByEmail} invited you as ${role}.\n\nAccept here: ${invitationUrl}\n\nThis invitation expires in 7 days.`,
  };
}

type VerificationEmailParams = {
  email: string;
  verificationUrl: string;
  appName?: string;
};

type PasswordResetEmailParams = {
  email: string;
  resetUrl: string;
  appName?: string;
};

export function verificationEmailTemplate(params: VerificationEmailParams): {
  subject: string;
  html: string;
  text: string;
} {
  const { email, verificationUrl, appName = 'Griffon' } = params;

  return {
    subject: `Verify your email — ${appName}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #1A1A2E;">Verify your email address</h2>
        <p>Hi ${email},</p>
        <p>Thanks for signing up for ${appName}. Please verify your email address by clicking the button below:</p>
        <a href="${verificationUrl}"
           style="display: inline-block; background: #4F8EF7; color: white;
                  padding: 12px 24px; border-radius: 6px; text-decoration: none;
                  font-weight: bold; margin: 16px 0;">
          Verify Email
        </a>
        <p style="color: #6B7280; font-size: 14px;">
          This link expires in 24 hours. If you did not create an account, ignore this email.
        </p>
        <p style="color: #6B7280; font-size: 12px;">
          Or copy this link: ${verificationUrl}
        </p>
      </div>
    `,
    text: `Verify your email for ${appName}.\n\nClick here: ${verificationUrl}\n\nThis link expires in 24 hours.`,
  };
}

export function passwordResetEmailTemplate(params: PasswordResetEmailParams): {
  subject: string;
  html: string;
  text: string;
} {
  const { email, resetUrl, appName = 'Griffon' } = params;

  return {
    subject: `Reset your password — ${appName}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #1A1A2E;">Reset your password</h2>
        <p>Hi ${email},</p>
        <p>We received a request to reset your password for your ${appName} account.</p>
        <a href="${resetUrl}"
           style="display: inline-block; background: #4F8EF7; color: white;
                  padding: 12px 24px; border-radius: 6px; text-decoration: none;
                  font-weight: bold; margin: 16px 0;">
          Reset Password
        </a>
        <p style="color: #6B7280; font-size: 14px;">
          This link expires in 1 hour. If you did not request a password reset, ignore this email.
        </p>
        <p style="color: #6B7280; font-size: 12px;">
          Or copy this link: ${resetUrl}
        </p>
      </div>
    `,
    text: `Reset your ${appName} password.\n\nClick here: ${resetUrl}\n\nThis link expires in 1 hour.`,
  };
}
