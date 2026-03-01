/**
 * php-rs for Deno — Run PHP on Deno Deploy and Deno runtime.
 *
 * ```ts
 * import { serve } from "https://raw.githubusercontent.com/php/php-rs/main/packages/php-rs-deno/mod.ts";
 *
 * serve({
 *   documentRoot: "/var/www",
 *   files: { "/index.php": "<?php echo 'Hello from Deno!';" },
 * });
 * ```
 *
 * @module
 */

import { PHP, createHttpHandler } from "../php-rs-wasm/src/index.ts";
import type { PhpConfig } from "../php-rs-wasm/src/index.ts";

export interface DenoServeOptions {
  /** PHP configuration. */
  config?: PhpConfig;
  /** PHP files to load into the VFS. */
  files?: Record<string, string>;
  /** Entry point file (default: "/index.php"). */
  entryPoint?: string;
  /** Port to listen on (default: 8000). */
  port?: number;
  /** Hostname to bind to (default: "0.0.0.0"). */
  hostname?: string;
}

/**
 * Start a Deno HTTP server that executes PHP scripts.
 */
export async function serve(options: DenoServeOptions = {}): Promise<void> {
  await PHP.init();
  const php = new PHP(options.config);

  if (options.files) {
    for (const [path, contents] of Object.entries(options.files)) {
      php.writeFile(path, contents);
    }
  }

  const handler = createHttpHandler(php);
  const port = options.port ?? 8000;
  const hostname = options.hostname ?? "0.0.0.0";

  console.log(`php.rs/deno listening on http://${hostname}:${port}`);

  Deno.serve({ port, hostname }, (request: Request) => {
    return handler.handleRequest(request, {
      entryPoint: options.entryPoint,
    });
  });
}

export { PHP, createHttpHandler };
export type { PhpConfig };
