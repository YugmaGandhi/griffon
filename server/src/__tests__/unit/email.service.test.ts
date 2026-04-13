// ── Mock logger before anything imports it ───────────────
jest.mock('../../utils/logger', () => ({
  createLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  }),
}));

// ── Mock nodemailer ──────────────────────────────────────
// Use a shared reference via module-scoped object so the hoisted
// jest.mock factory and the test code share the same mock fn
const sendMailHolder: { fn: jest.Mock } = { fn: jest.fn() };

jest.mock('nodemailer', () => ({
  createTransport: jest.fn(() => ({
    sendMail: (...args: unknown[]) => sendMailHolder.fn(...args),
  })),
}));

// Mock env to avoid needing real env vars
jest.mock('../../config/env', () => ({
  env: {
    EMAIL_PROVIDER: 'smtp',
    SMTP_HOST: 'localhost',
    SMTP_PORT: 1025,
    SMTP_USER: undefined,
    SMTP_PASS: undefined,
    RESEND_API_KEY: undefined,
    APP_BASE_URL: 'http://localhost:3000',
    EMAIL_FROM: 'noreply@griffon.dev',
    EMAIL_FROM_NAME: 'Griffon',
  },
}));

// Mock email templates
jest.mock('../../utils/email-templates', () => ({
  verificationEmailTemplate: jest.fn(
    ({
      email,
      verificationUrl,
    }: {
      email: string;
      verificationUrl: string;
    }) => ({
      subject: 'Verify your email',
      html: `<p>Hello ${email}, verify at ${verificationUrl}</p>`,
      text: `Hello ${email}, verify at ${verificationUrl}`,
    })
  ),
  passwordResetEmailTemplate: jest.fn(
    ({ email, resetUrl }: { email: string; resetUrl: string }) => ({
      subject: 'Reset your password',
      html: `<p>Hello ${email}, reset at ${resetUrl}</p>`,
      text: `Hello ${email}, reset at ${resetUrl}`,
    })
  ),
}));

import { EmailService } from '../../services/email.service';

let emailService: EmailService;

beforeEach(() => {
  sendMailHolder.fn = jest.fn();
  emailService = new EmailService();
});

describe('EmailService', () => {
  // ── sendVerificationEmail() ─────────────────────────────
  describe('sendVerificationEmail()', () => {
    it('should send verification email with correct parameters', async () => {
      sendMailHolder.fn.mockResolvedValue({ messageId: 'test-id' });

      await emailService.sendVerificationEmail(
        'user@example.com',
        'abc123token'
      );

      expect(sendMailHolder.fn).toHaveBeenCalledTimes(1);
      expect(sendMailHolder.fn).toHaveBeenCalledWith(
        expect.objectContaining({
          from: '"Griffon" <noreply@griffon.dev>',
          to: 'user@example.com',
          subject: 'Verify your email',
        })
      );
    });

    it('should include verification URL with token in email body', async () => {
      sendMailHolder.fn.mockResolvedValue({ messageId: 'test-id' });

      await emailService.sendVerificationEmail(
        'user@example.com',
        'abc123token'
      );

      const callArgs = sendMailHolder.fn.mock.calls[0][0];
      expect(callArgs.html).toContain(
        'http://localhost:3000/auth/verify-email?token=abc123token'
      );
      expect(callArgs.text).toContain(
        'http://localhost:3000/auth/verify-email?token=abc123token'
      );
    });

    it('should throw when sendMail fails', async () => {
      sendMailHolder.fn.mockRejectedValue(new Error('SMTP connection failed'));

      await expect(
        emailService.sendVerificationEmail('user@example.com', 'token')
      ).rejects.toThrow('Failed to send verification email');
    });
  });

  // ── sendPasswordResetEmail() ────────────────────────────
  describe('sendPasswordResetEmail()', () => {
    it('should send password reset email with correct parameters', async () => {
      sendMailHolder.fn.mockResolvedValue({ messageId: 'test-id' });

      await emailService.sendPasswordResetEmail(
        'user@example.com',
        'reset-token-xyz'
      );

      expect(sendMailHolder.fn).toHaveBeenCalledTimes(1);
      expect(sendMailHolder.fn).toHaveBeenCalledWith(
        expect.objectContaining({
          from: '"Griffon" <noreply@griffon.dev>',
          to: 'user@example.com',
          subject: 'Reset your password',
        })
      );
    });

    it('should include reset URL with token in email body', async () => {
      sendMailHolder.fn.mockResolvedValue({ messageId: 'test-id' });

      await emailService.sendPasswordResetEmail(
        'user@example.com',
        'reset-token-xyz'
      );

      const callArgs = sendMailHolder.fn.mock.calls[0][0];
      expect(callArgs.html).toContain(
        'http://localhost:3000/auth/reset-password?token=reset-token-xyz'
      );
      expect(callArgs.text).toContain(
        'http://localhost:3000/auth/reset-password?token=reset-token-xyz'
      );
    });

    it('should throw when sendMail fails', async () => {
      sendMailHolder.fn.mockRejectedValue(new Error('SMTP timeout'));

      await expect(
        emailService.sendPasswordResetEmail('user@example.com', 'token')
      ).rejects.toThrow('Failed to send password reset email');
    });
  });
});
