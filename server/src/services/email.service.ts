import nodemailer from 'nodemailer';
import { env } from '../config/env';
import { createLogger } from '../utils/logger';
import {
  verificationEmailTemplate,
  passwordResetEmailTemplate,
  orgInvitationEmailTemplate,
} from '../utils/email-templates';

const log = createLogger('EmailService');

export class EmailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = this.createTransporter();
  }

  private createTransporter(): nodemailer.Transporter {
    if (env.EMAIL_PROVIDER === 'smtp') {
      return nodemailer.createTransport({
        host: env.SMTP_HOST ?? 'localhost',
        port: env.SMTP_PORT,
        secure: false, // true for 465, false for other ports
        auth:
          env.SMTP_USER && env.SMTP_PASS
            ? { user: env.SMTP_USER, pass: env.SMTP_PASS }
            : undefined,
      });
    }

    // Resend provider — uses SMTP under the hood
    return nodemailer.createTransport({
      host: 'smtp.resend.com',
      port: 465,
      secure: true,
      auth: {
        user: 'resend',
        pass: env.RESEND_API_KEY ?? '',
      },
    });
  }

  async sendVerificationEmail(email: string, token: string): Promise<void> {
    const verificationUrl = `${env.APP_BASE_URL}/auth/verify-email?token=${token}`;
    const template = verificationEmailTemplate({ email, verificationUrl });

    log.info({ email }, 'Sending verification email');

    try {
      await this.transporter.sendMail({
        from: `"${env.EMAIL_FROM_NAME}" <${env.EMAIL_FROM}>`,
        to: email,
        subject: template.subject,
        html: template.html,
        text: template.text,
      });

      log.info({ email }, 'Verification email sent');
    } catch (err) {
      log.error({ err, email }, 'Failed to send verification email');
      throw new Error('Failed to send verification email');
    }
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    const resetUrl = `${env.APP_BASE_URL}/auth/reset-password?token=${token}`;
    const template = passwordResetEmailTemplate({ email, resetUrl });

    log.info({ email }, 'Sending password reset email');

    try {
      await this.transporter.sendMail({
        from: `"${env.EMAIL_FROM_NAME}" <${env.EMAIL_FROM}>`,
        to: email,
        subject: template.subject,
        html: template.html,
        text: template.text,
      });

      log.info({ email }, 'Password reset email sent');
    } catch (err) {
      log.error({ err, email }, 'Failed to send password reset email');
      throw new Error('Failed to send password reset email');
    }
  }
  async sendOrgInvitationEmail(params: {
    email: string;
    token: string;
    orgName: string;
    invitedByEmail: string;
    role: string;
  }): Promise<void> {
    const invitationUrl = `${env.APP_BASE_URL}/auth/accept-invitation?token=${params.token}`;
    const template = orgInvitationEmailTemplate({
      email: params.email,
      invitationUrl,
      orgName: params.orgName,
      invitedByEmail: params.invitedByEmail,
      role: params.role,
    });

    log.info(
      { email: params.email, orgName: params.orgName },
      'Sending org invitation email'
    );

    try {
      await this.transporter.sendMail({
        from: `"${env.EMAIL_FROM_NAME}" <${env.EMAIL_FROM}>`,
        to: params.email,
        subject: template.subject,
        html: template.html,
        text: template.text,
      });

      log.info({ email: params.email }, 'Org invitation email sent');
    } catch (err) {
      log.error(
        { err, email: params.email },
        'Failed to send org invitation email'
      );
      throw new Error('Failed to send invitation email');
    }
  }
}

export const emailService = new EmailService();
