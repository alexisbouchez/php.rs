import { PHP, createHttpHandler } from "php-rs-wasm";
import type { PhpConfig } from "php-rs-wasm";

export interface WorkerConfig {
  /** PHP configuration (INI settings, env vars, etc.). */
  config?: PhpConfig;
  /** PHP files to pre-load into the VFS. Keys are paths, values are file contents. */
  files?: Record<string, string>;
  /** Entry point PHP file (default: "/index.php"). */
  entryPoint?: string;
}

/**
 * Create a Cloudflare Worker handler that executes PHP.
 *
 * ```ts
 * import { createWorker } from "php-rs-cloudflare-worker";
 *
 * const worker = createWorker({
 *   files: { "/index.php": "<?php echo 'Hello from the edge!';" },
 * });
 *
 * export default worker;
 * ```
 */
export function createWorker(workerConfig: WorkerConfig = {}): ExportedHandler {
  let php: PHP | null = null;

  async function getPhp(): Promise<PHP> {
    if (!php) {
      await PHP.init();
      php = new PHP(workerConfig.config);

      // Load files into VFS
      if (workerConfig.files) {
        for (const [path, contents] of Object.entries(workerConfig.files)) {
          php.writeFile(path, contents);
        }
      }
    }
    return php;
  }

  return {
    async fetch(request: Request): Promise<Response> {
      const instance = await getPhp();
      const handler = createHttpHandler(instance);
      return handler.handleRequest(request, {
        entryPoint: workerConfig.entryPoint,
      });
    },
  };
}

// Default export for simple usage
export default {
  async fetch(request: Request): Promise<Response> {
    await PHP.init();
    const php = new PHP();
    const handler = createHttpHandler(php);
    try {
      return handler.handleRequest(request);
    } finally {
      php.dispose();
    }
  },
};
