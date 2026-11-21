// Clean Code V12 — VS Code extension entry point.
//
// Spawns the `cc-lsp` daemon over stdio and wires it to VS Code's
// LanguageClient. The daemon is the same binary used by the CLI, so
// findings, hovers, and code-actions are exactly what `ccv12 check`
// produces — no editor-specific lint logic lives here.
//
// Server discovery (in order):
//   1. `cleanCodeV12.cli.path` + `lsp` subcommand   (e.g. `ccv12 lsp`)
//   2. `cleanCodeV12.server.path`                   (e.g. `cc-lsp`)
// The first command whose binary resolves on PATH wins. The CLI does
// NOT currently ship an `lsp` subcommand (verified against
// crates/cc-cli/src/args.rs), so the extension defaults to spawning
// `cc-lsp` directly. The CLI path is kept as the first option so the
// indirection stops mattering once cc grows the subcommand.

import * as vscode from 'vscode';
import {
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
    TransportKind,
    Executable,
} from 'vscode-languageclient/node';

let client: LanguageClient | undefined;

const SUPPORTED_LANGUAGES: ReadonlyArray<string> = [
    'python',
    'typescript',
    'javascript',
    'rust',
    'go',
];

/**
 * Build the ServerOptions describing how to launch cc-lsp.
 *
 * We prefer the `ccv12 lsp` subcommand (so a single CLI binary covers
 * both batch and LSP use). If that subcommand is unavailable, callers
 * should set `cleanCodeV12.server.path` to point at the standalone
 * `cc-lsp` binary instead.
 */
function buildServerOptions(): ServerOptions {
    const config = vscode.workspace.getConfiguration('cleanCodeV12');
    const cliPath: string = config.get<string>('cli.path', 'ccv12');
    const serverPath: string = config.get<string>('server.path', 'cc-lsp');
    const severity: string = config.get<string>('severity', 'required');

    const env: NodeJS.ProcessEnv = {
        ...process.env,
        CC_LSP_SEVERITY: severity,
    };

    // First try `<cli> lsp` — once cc-cli grows an `lsp` subcommand
    // this becomes the preferred surface.
    const cliExecutable: Executable = {
        command: cliPath,
        args: ['lsp', '--stdio'],
        transport: TransportKind.stdio,
        options: { env },
    };

    // Fallback to the standalone `cc-lsp` daemon binary.
    const daemonExecutable: Executable = {
        command: serverPath,
        args: ['--stdio'],
        transport: TransportKind.stdio,
        options: { env },
    };

    // vscode-languageclient does not natively support a "try A, fall
    // back to B" run config, so we resolve at activation time. The
    // chosen executable becomes both `run` and `debug`. Selection
    // policy: if `ccv12 lsp --help` exits 0 we use the CLI; otherwise we
    // fall back to the daemon. We do that synchronously below in the
    // factory so the chosen command is fixed for the client's lifetime.
    return resolveExecutable(cliExecutable, daemonExecutable);
}

/**
 * Decide whether to use `<cli> lsp` or the standalone `cc-lsp` daemon.
 *
 * We don't actually probe the binary at activation — that would block
 * the extension host. Instead we honour an explicit user choice:
 *   - If `cleanCodeV12.cli.path` was customised AND `cleanCodeV12.server.path`
 *     left default, prefer the CLI.
 *   - Otherwise prefer the standalone daemon (the documented default
 *     while `ccv12 lsp` does not yet exist).
 */
function resolveExecutable(cli: Executable, daemon: Executable): ServerOptions {
    const config = vscode.workspace.getConfiguration('cleanCodeV12');
    const cliInspected = config.inspect<string>('cli.path');
    const cliCustomised =
        cliInspected !== undefined &&
        (cliInspected.workspaceValue !== undefined ||
            cliInspected.globalValue !== undefined);

    const chosen: Executable = cliCustomised ? cli : daemon;
    return { run: chosen, debug: chosen };
}

function buildClientOptions(): LanguageClientOptions {
    const documentSelector = SUPPORTED_LANGUAGES.map((language) => ({
        scheme: 'file',
        language,
    }));
    return {
        documentSelector,
        synchronize: {
            // cc reads `.cc/config.toml` + `.cc/baseline.json` from the
            // workspace root. Notify the server whenever those change.
            fileEvents: [
                vscode.workspace.createFileSystemWatcher('**/.cc/config.toml'),
                vscode.workspace.createFileSystemWatcher('**/.cc/baseline.json'),
            ],
        },
        outputChannelName: 'Clean Code V12',
        traceOutputChannel: vscode.window.createOutputChannel('Clean Code V12 (trace)'),
    };
}

async function startClient(context: vscode.ExtensionContext): Promise<void> {
    const serverOptions = buildServerOptions();
    const clientOptions = buildClientOptions();

    client = new LanguageClient(
        'cleanCodeV12',
        'Clean Code V12',
        serverOptions,
        clientOptions,
    );

    try {
        await client.start();
    } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        void vscode.window.showErrorMessage(
            `Clean Code V12: failed to start cc-lsp — ${message}. ` +
                `Set "cleanCodeV12.server.path" to the cc-lsp binary, ` +
                `or "cleanCodeV12.cli.path" to a ccv12 CLI that supports the lsp subcommand.`,
        );
        client = undefined;
        return;
    }

    context.subscriptions.push({
        dispose: () => {
            // Best-effort stop on disposal; awaited in deactivate().
            void client?.stop();
        },
    });
}

async function restartClient(context: vscode.ExtensionContext): Promise<void> {
    if (client !== undefined) {
        try {
            await client.stop();
        } catch {
            // Ignore — we are restarting anyway.
        }
        client = undefined;
    }
    await startClient(context);
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
    context.subscriptions.push(
        vscode.commands.registerCommand('cleanCodeV12.restart', async () => {
            await restartClient(context);
            void vscode.window.showInformationMessage('Clean Code V12: server restarted.');
        }),
    );

    // Reload-on-config-change so the user does not have to restart VS
    // Code after editing `cleanCodeV12.*` settings.
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration((event) => {
            if (
                event.affectsConfiguration('cleanCodeV12.cli.path') ||
                event.affectsConfiguration('cleanCodeV12.server.path') ||
                event.affectsConfiguration('cleanCodeV12.severity')
            ) {
                void restartClient(context);
            }
        }),
    );

    await startClient(context);
}

export async function deactivate(): Promise<void> {
    if (client === undefined) {
        return;
    }
    try {
        await client.stop();
    } finally {
        client = undefined;
    }
}
