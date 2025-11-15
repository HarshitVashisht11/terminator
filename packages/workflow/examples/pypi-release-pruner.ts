import * as workflowLib from '@mediar-ai/workflow';
import crypto from 'node:crypto';
import { z } from 'zod';

const { createStep, createWorkflow } = workflowLib;

type WorkflowInput = {
  username: string;
  password: string;
  totpSecret: string;
  projectSlug: string;
  releasesUrl?: string;
  alwaysDeleteOldest: boolean;
  maxReleasesBeforeDelete: number;
  waitMs: number;
};

const workflowInput: z.ZodType<WorkflowInput> = z
  .object({
  username: z.string().min(1, 'PyPI username is required'),
  password: z.string().min(1, 'PyPI password is required'),
  totpSecret: z.string().min(10, 'PyPI TOTP secret is required'),
  projectSlug: z.string().min(1).default('terminator'),
  releasesUrl: z.string().url().optional(),
  alwaysDeleteOldest: z.boolean().default(true),
  maxReleasesBeforeDelete: z.number().int().min(1).max(500).default(200),
  waitMs: z.number().int().min(1000).max(10000).default(3500),
  }) as z.ZodType<WorkflowInput>;

type SharedState = {
  loginPageOpened?: boolean;
  credentialsSubmitted?: boolean;
  totpAttempted?: boolean;
  releasesUrl?: string;
  releaseCount?: number;
  targetVersion?: string;
  targetModalSlug?: string;
  shouldDelete?: boolean;
  deletionTriggered?: boolean;
  lastDeletedVersion?: string;
  remainingAfterDeletion?: number;
  summaryRecorded?: boolean;
};

type StepState = Partial<SharedState>;

interface BrowserResult<T = Record<string, unknown>> {
  error?: string;
  [key: string]: any;
  data?: T;
}

async function getBrowserWindow(desktop: any) {
  const browserWindow = await desktop.getCurrentBrowserWindow();
  if (!browserWindow) {
    throw new Error('Unable to locate an active browser window');
  }
  return browserWindow;
}

async function runBrowserJSON<T extends BrowserResult>(
  browserWindow: any,
  body: string
): Promise<T> {
  const script = `
    (() => {
      try {
        const result = (() => {
          ${body}
        })();
        if (typeof result === 'string') {
          return result;
        }
        return JSON.stringify(result);
      } catch (error) {
        return JSON.stringify({ error: error?.message || String(error) });
      }
    })()
  `;

  const rawResult = await browserWindow.executeBrowserScript(script);

  try {
    return JSON.parse(rawResult) as T;
  } catch (error) {
    throw new Error(`Unable to parse browser script response: ${rawResult}`);
  }
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32ToBuffer(secret: string): Buffer {
  const normalized = secret.toUpperCase().replace(/[^A-Z2-7]/g, '');
  if (!normalized.length) {
    throw new Error('Invalid TOTP secret');
  }

  let bits = '';
  for (const char of normalized) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) {
      throw new Error(`Invalid base32 character encountered: ${char}`);
    }
    bits += idx.toString(2).padStart(5, '0');
  }

  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }

  return Buffer.from(bytes);
}

function generateTotp(secret: string, timestampMs = Date.now()): string {
  const key = base32ToBuffer(secret);
  const timeStep = 30;
  const counter = Math.floor(timestampMs / 1000 / timeStep);
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));

  const digest = crypto.createHmac('sha1', key).update(buffer).digest();
  const offset = digest[digest.length - 1] & 0xf;
  const code =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  const otp = (code % 1_000_000).toString().padStart(6, '0');

  return otp;
}

const openLoginStep = createStep<WorkflowInput, void, {}, StepState>({
  id: 'open-pypi-login',
  name: 'Open PyPI login page',
  execute: async ({ desktop, logger }) => {
    logger.info('Opening PyPI login page...');
    await desktop.openUrl('https://pypi.org/account/login/');
    await desktop.delay(2500);

    const browserWindow = await getBrowserWindow(desktop);
    const pageTitle = await browserWindow.name();
    logger.info(`Focused window: ${pageTitle ?? 'Unknown window'}`);

    return {
      state: {
        loginPageOpened: true,
      },
    };
  },
});

const submitCredentialsStep = createStep<WorkflowInput, void, StepState, StepState>({
  id: 'fill-credentials',
  name: 'Fill username and password',
  condition: ({ context }) => context.state.loginPageOpened === true,
  execute: async ({ desktop, logger, input }) => {
    const browserWindow = await getBrowserWindow(desktop);
    logger.info('Submitting username and password...');

    const domResult = await runBrowserJSON(browserWindow, `
      const usernameInput = document.querySelector('input[name="username"]');
      const passwordInput = document.querySelector('input[name="password"]');
      const submitButton = document.querySelector('form[action="/account/login/"] button[type="submit"]');

      if (!usernameInput || !passwordInput || !submitButton) {
        return { error: 'Unable to locate PyPI login form elements' };
      }

      usernameInput.focus();
      usernameInput.value = ${JSON.stringify(input.username)};
      usernameInput.dispatchEvent(new Event('input', { bubbles: true }));

      passwordInput.focus();
      passwordInput.value = ${JSON.stringify(input.password)};
      passwordInput.dispatchEvent(new Event('input', { bubbles: true }));

      submitButton.click();
      return { success: true };
    `);

    if (domResult.error) {
      throw new Error(domResult.error);
    }

    await desktop.delay(input.waitMs);

    return {
      state: {
        credentialsSubmitted: true,
      },
    };
  },
});

const totpStep = createStep<WorkflowInput, void, StepState, StepState>({
  id: 'submit-totp',
  name: 'Complete TOTP challenge',
  execute: async ({ desktop, logger, input }) => {
    const browserWindow = await getBrowserWindow(desktop);
    const checkResult = await runBrowserJSON<{ present?: boolean; error?: string }>(
      browserWindow,
      `
        const totpField = document.querySelector('input[name="totp_value"]');
        return { present: Boolean(totpField) };
      `
    );

    if (checkResult.error) {
      throw new Error(checkResult.error);
    }

    if (!checkResult.present) {
      logger.info('No TOTP prompt detected, continuing...');
      return {
        state: {
          totpAttempted: false,
        },
      };
    }

    const code = generateTotp(input.totpSecret);
    logger.info('Submitting TOTP code...');

    const totpResult = await runBrowserJSON(browserWindow, `
      const totpField = document.querySelector('input[name="totp_value"]');
      const submitButton = document.querySelector('#totp-auth-form input[type="submit"]');

      if (!totpField || !submitButton) {
        return { error: 'Unable to locate the TOTP verification form' };
      }

      totpField.focus();
      totpField.value = ${JSON.stringify(code)};
      totpField.dispatchEvent(new Event('input', { bubbles: true }));
      submitButton.click();

      return { success: true };
    `);

    if (totpResult.error) {
      throw new Error(totpResult.error);
    }

    await desktop.delay(input.waitMs);

    return {
      state: {
        totpAttempted: true,
      },
    };
  },
});

const navigateToReleasesStep = createStep<WorkflowInput, void, StepState, StepState>({
  id: 'open-releases',
  name: 'Open project releases page',
  execute: async ({ desktop, logger, input }) => {
    const releasesUrl =
      input.releasesUrl ??
      `https://pypi.org/manage/project/${encodeURIComponent(input.projectSlug)}/releases/`;

    const browserWindow = await getBrowserWindow(desktop);
    logger.info(`Navigating to ${releasesUrl} ...`);

    const navResult = await runBrowserJSON(browserWindow, `
      const targetUrl = ${JSON.stringify(releasesUrl)};
      if (window.location.href === targetUrl) {
        window.location.reload();
      } else {
        window.location.href = targetUrl;
      }
      return { navigating: true };
    `);

    if (navResult.error) {
      throw new Error(navResult.error);
    }

    await desktop.delay(input.waitMs);

    return {
      state: {
        releasesUrl,
      },
    };
  },
});

const inspectReleasesStep = createStep<WorkflowInput, void, StepState, StepState>({
  id: 'inspect-releases',
  name: 'Evaluate release table',
  execute: async ({ desktop, logger, input }) => {
    const browserWindow = await getBrowserWindow(desktop);

    const releasesInfo = await runBrowserJSON<{
      total?: number;
      versions?: Array<string | null>;
      slugs?: Array<string | null>;
      error?: string;
    }>(browserWindow, `
      const rows = Array.from(document.querySelectorAll('table.table--releases tbody tr'));
      if (!rows.length) {
        return { total: 0 };
      }

      const versions = rows.map(row => {
        const link = row.querySelector('th a');
        return link ? link.textContent?.trim() || null : null;
      });

      const slugs = rows.map(row => {
        const action = row.querySelector('a[href^="#delete_release-modal"]');
        return action ? action.getAttribute('href') : null;
      });

      return {
        total: rows.length,
        versions,
        slugs,
      };
    `);

    if (releasesInfo.error) {
      throw new Error(releasesInfo.error);
    }

    const total = releasesInfo.total ?? 0;
    if (total === 0) {
      throw new Error('No releases found for this project');
    }

    const targetIndex = total - 1;
    const targetVersion = releasesInfo.versions?.[targetIndex]?.trim() || null;
    const rawSlug = releasesInfo.slugs?.[targetIndex] || null;

    if (!targetVersion || !rawSlug) {
      throw new Error('Unable to resolve delete action for the oldest release');
    }

    const shouldDelete =
      input.alwaysDeleteOldest || total >= input.maxReleasesBeforeDelete;

    if (!shouldDelete) {
      logger.info(
        `Currently ${total} releases, below threshold ${input.maxReleasesBeforeDelete}. Skipping deletion.`
      );
    } else {
      logger.info(
        `Preparing to delete version ${targetVersion} (row ${targetIndex + 1}/${total}).`
      );
    }

    return {
      state: {
        releaseCount: total,
        targetVersion,
        targetModalSlug: rawSlug.replace('#', ''),
        shouldDelete,
      },
    };
  },
});

const deleteReleaseStep = createStep<WorkflowInput, void, StepState, StepState>({
  id: 'delete-oldest-release',
  name: 'Delete oldest PyPI release',
  condition: ({ context }) =>
    Boolean(context.state.shouldDelete && context.state.targetVersion && context.state.targetModalSlug),
  execute: async ({ desktop, context, logger }) => {
    const browserWindow = await getBrowserWindow(desktop);
    const version = context.state.targetVersion as string;
    const slug = context.state.targetModalSlug as string;

    logger.warn(`Deleting oldest release ${version} ...`);

    const modalResult = await runBrowserJSON(browserWindow, `
      const slug = ${JSON.stringify(slug)};
      const version = ${JSON.stringify(version)};
      const modal = document.getElementById(slug);
      const confirmInput = modal ? modal.querySelector('input[name="confirm_delete_version"]') : null;
      const confirmButton = modal ? modal.querySelector('button.js-confirm') : null;

      if (!modal || !confirmInput || !confirmButton) {
        return { error: 'Unable to locate delete confirmation modal' };
      }

      confirmInput.focus();
      confirmInput.value = version;
      confirmInput.dispatchEvent(new Event('input', { bubbles: true }));
      confirmButton.removeAttribute('disabled');
      confirmButton.click();

      return { submitted: true };
    `);

    if (modalResult.error) {
      throw new Error(modalResult.error);
    }

    await desktop.delay(2000);

    return {
      state: {
        deletionTriggered: true,
        lastDeletedVersion: version,
      },
    };
  },
});

const verifyDeletionStep = createStep<WorkflowInput, void, StepState, StepState>({
  id: 'verify-deletion',
  name: 'Verify release removal',
  condition: ({ context }) => Boolean(context.state.deletionTriggered),
  execute: async ({ desktop, logger, context }) => {
    const browserWindow = await getBrowserWindow(desktop);
    await desktop.delay(2000);

    const verifyResult = await runBrowserJSON<{
      versions?: string[];
      total?: number;
      error?: string;
    }>(browserWindow, `
      const entries = Array.from(document.querySelectorAll('table.table--releases tbody th a'));
      return {
        total: entries.length,
        versions: entries.map(link => link.textContent?.trim()).filter(Boolean),
      };
    `);

    if (verifyResult.error) {
      throw new Error(verifyResult.error);
    }

    const remaining = verifyResult.total ?? 0;
    const versionList = verifyResult.versions ?? [];
    const deletedVersion = context.state.lastDeletedVersion as string;

    if (versionList.includes(deletedVersion)) {
      throw new Error(`Release ${deletedVersion} still present after deletion attempt`);
    }

    logger.success(`Release ${deletedVersion} removed. ${remaining} releases remain.`);

    return {
      state: {
        remainingAfterDeletion: remaining,
      },
    };
  },
});

const finalizeStep = createStep<WorkflowInput, void, StepState, StepState>({
  id: 'finalize-cleanup',
  name: 'Record cleanup summary',
  execute: async ({ context, logger, input }) => {
    const deletionExecuted = Boolean(context.state.deletionTriggered);
    const deletedVersion = context.state.lastDeletedVersion ?? null;

    if (!deletionExecuted) {
      logger.info('No deletion was required for this run.');
    }

    const summary = {
      project: input.projectSlug,
      deletedVersion,
      releaseCountBefore: context.state.releaseCount ?? 0,
      releaseCountAfter:
        context.state.remainingAfterDeletion ?? context.state.releaseCount ?? 0,
      deletionExecuted,
      timestamp: new Date().toISOString(),
    };

    context.data = summary;

    return {
      state: {
        summaryRecorded: true,
      },
    };
  },
});

const workflowBase = createWorkflow<WorkflowInput>({
  name: 'PyPI release pruner',
  description:
    'Opens PyPI, logs in with TOTP, and deletes the oldest release before publishing.',
  version: '1.0.0',
  input: workflowInput,
});

const workflow =
  'step' in workflowBase
    ? workflowBase
        .step(openLoginStep)
        .step(submitCredentialsStep)
        .step(totpStep)
        .step(navigateToReleasesStep)
        .step(inspectReleasesStep)
        .step(deleteReleaseStep)
        .step(verifyDeletionStep)
        .step(finalizeStep)
        .build()
    : workflowBase;

export default workflow;

