import { PHP } from "./php.js";
import type { PhpRequest } from "./types.js";

export interface HttpHandlerOptions {
  /** PHP entry point file (default: "/index.php"). */
  entryPoint?: string;
}

export interface HttpHandler {
  /** Handle a standard Request and return a Response. */
  handleRequest(request: Request, options?: HttpHandlerOptions): Response;
}

/**
 * Create an HTTP handler that routes web Requests through a PHP runtime.
 *
 * Maps Request → superglobals → PHP execution → Response.
 *
 * ```ts
 * const php = new PHP();
 * const handler = createHttpHandler(php);
 * const response = handler.handleRequest(new Request("https://example.com/?name=world"));
 * ```
 */
export function createHttpHandler(php: PHP): HttpHandler {
  return {
    handleRequest(request: Request, options?: HttpHandlerOptions): Response {
      const url = new URL(request.url);
      const entryPoint = options?.entryPoint ?? "/index.php";

      const headers: Record<string, string> = {};
      request.headers.forEach((value, key) => {
        headers[key] = value;
      });

      const phpRequest: PhpRequest = {
        method: request.method,
        url: url.pathname + url.search,
        headers,
        body: undefined,
      };

      // Read body synchronously (edge runtimes may support this)
      // For async bodies, the caller should await request.text() before calling
      if (request.method !== "GET" && request.method !== "HEAD") {
        // Note: body reading is synchronous in this context.
        // For async bodies, use: phpRequest.body = await request.text()
        // before calling handleRequest.
      }

      const code = `<?php require '${entryPoint}';`;
      const result = php.request(code, phpRequest);

      const responseHeaders = new Headers();
      for (const header of result.headers) {
        const colonIdx = header.indexOf(":");
        if (colonIdx !== -1) {
          const name = header.substring(0, colonIdx).trim();
          const value = header.substring(colonIdx + 1).trim();
          responseHeaders.set(name, value);
        }
      }

      return new Response(result.output, {
        status: result.statusCode,
        headers: responseHeaders,
      });
    },
  };
}
