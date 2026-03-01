import type { PhpConfig, PhpRequest, PhpResponse, Token } from "./types.js";

/**
 * Raw wasm-bindgen interface. This matches the shape exported by
 * `wasm-pack build --target web` for the `PhpWasm` class.
 */
interface PhpWasmRaw {
  new (): PhpWasmRaw;
  free(): void;

  // VFS
  write_file(path: string, contents: Uint8Array): void;
  read_file(path: string): Uint8Array;
  file_exists(path: string): boolean;
  list_dir(path: string): string;
  remove_file(path: string): void;
  mkdir(path: string): void;

  // Execution
  eval(code: string): string;
  exec_file(path: string): string;
  run(code: string): { output: string; headers: string; statusCode: number };

  // Config
  set_ini(key: string, value: string): void;
  set_env(name: string, value: string): void;
  set_get_params(query_string: string): void;
  set_post_body(body: string, content_type: string): void;
  set_cookies(cookie_header: string): void;
  set_server_var(key: string, value: string): void;
  set_request_body(body: Uint8Array): void;
  set_persistent(mode: boolean): void;

  // JS Interop
  register_function(name: string, callback: Function): void;
  set_output_handler(callback: Function): void;
  set_fetch_handler(callback: Function): void;

  // Introspection
  tokenize(code: string): string;
  parse(code: string): string;

  // Lifecycle
  reset(): void;
  php_version(): string;
  loaded_extensions(): string;
}

interface WasmModule {
  default: (input?: string | URL | Request) => Promise<void>;
  PhpWasm: { new (): PhpWasmRaw };
}

let wasmModule: WasmModule | null = null;

/**
 * High-level PHP runtime for browser and edge environments.
 *
 * ```ts
 * await PHP.init();
 * const php = new PHP({ ini: { display_errors: "0" } });
 * const response = php.run("<?php echo 'Hello!';");
 * console.log(response.output); // "Hello!"
 * php.dispose();
 * ```
 */
export class PHP {
  private inner: PhpWasmRaw;
  private disposed = false;

  /**
   * Initialize the WASM module. Must be called once before creating instances.
   * @param wasmUrl - Optional URL to the .wasm file. If omitted, uses the default bundled path.
   */
  static async init(wasmUrl?: string | URL): Promise<void> {
    if (wasmModule) return;
    // Dynamic import of the wasm-pack generated JS glue
    const mod = (await import(
      /* webpackIgnore: true */ "../../wasm/php_rs_sapi_wasm.js"
    )) as WasmModule;
    await mod.default(wasmUrl);
    wasmModule = mod;
  }

  constructor(config?: PhpConfig) {
    if (!wasmModule) {
      throw new Error(
        "PHP.init() must be called before creating PHP instances"
      );
    }
    this.inner = new wasmModule.PhpWasm();

    if (config?.ini) {
      for (const [key, value] of Object.entries(config.ini)) {
        this.inner.set_ini(key, value);
      }
    }
    if (config?.env) {
      for (const [key, value] of Object.entries(config.env)) {
        this.inner.set_env(key, value);
      }
    }
    if (config?.persistent) {
      this.inner.set_persistent(true);
    }
  }

  /** Execute PHP code and return a structured response. */
  run(code: string): PhpResponse {
    this.assertNotDisposed();
    const result = this.inner.run(code);
    return {
      output: result.output,
      headers: JSON.parse(result.headers),
      statusCode: result.statusCode,
    };
  }

  /**
   * Execute PHP code with an HTTP-like request context.
   * Populates $_GET, $_POST, $_COOKIE, $_SERVER from the request.
   */
  request(code: string, req: PhpRequest): PhpResponse {
    this.assertNotDisposed();

    if (req.method) {
      this.inner.set_server_var("REQUEST_METHOD", req.method);
    }
    if (req.url) {
      this.inner.set_server_var("REQUEST_URI", req.url);
      const qIdx = req.url.indexOf("?");
      if (qIdx !== -1) {
        this.inner.set_get_params(req.url.substring(qIdx + 1));
      }
    }
    if (req.headers) {
      for (const [key, value] of Object.entries(req.headers)) {
        const serverKey = "HTTP_" + key.toUpperCase().replace(/-/g, "_");
        this.inner.set_server_var(serverKey, value);

        if (key.toLowerCase() === "cookie") {
          this.inner.set_cookies(value);
        }
        if (key.toLowerCase() === "content-type") {
          this.inner.set_server_var("CONTENT_TYPE", value);
          if (req.body) {
            this.inner.set_post_body(req.body, value);
          }
        }
      }
    }
    if (req.body) {
      this.inner.set_request_body(new TextEncoder().encode(req.body));
    }

    return this.run(code);
  }

  /** Execute a file from the virtual filesystem. */
  execFile(path: string): PhpResponse {
    this.assertNotDisposed();
    const output = this.inner.exec_file(path);
    return { output, headers: [], statusCode: 200 };
  }

  /** Tokenize PHP code and return structured tokens. */
  tokenize(code: string): Token[] {
    this.assertNotDisposed();
    return JSON.parse(this.inner.tokenize(code));
  }

  /** Parse PHP code and return the AST as a JSON object. */
  parse(code: string): object {
    this.assertNotDisposed();
    return JSON.parse(this.inner.parse(code));
  }

  // ── VFS ──

  writeFile(path: string, contents: string | Uint8Array): void {
    this.assertNotDisposed();
    const data =
      typeof contents === "string"
        ? new TextEncoder().encode(contents)
        : contents;
    this.inner.write_file(path, data);
  }

  readFile(path: string): Uint8Array {
    this.assertNotDisposed();
    return this.inner.read_file(path);
  }

  fileExists(path: string): boolean {
    this.assertNotDisposed();
    return this.inner.file_exists(path);
  }

  listDir(path: string): string[] {
    this.assertNotDisposed();
    return JSON.parse(this.inner.list_dir(path));
  }

  removeFile(path: string): void {
    this.assertNotDisposed();
    this.inner.remove_file(path);
  }

  mkdir(path: string): void {
    this.assertNotDisposed();
    this.inner.mkdir(path);
  }

  // ── JS Interop ──

  /** Register a JS function callable from PHP. */
  registerFunction(name: string, callback: (...args: unknown[]) => unknown): void {
    this.assertNotDisposed();
    this.inner.register_function(name, callback);
  }

  /** Set a callback for real-time output streaming. */
  setOutputHandler(callback: (chunk: string) => void): void {
    this.assertNotDisposed();
    this.inner.set_output_handler(callback);
  }

  /** Set a callback for fetching URLs from PHP. */
  setFetchHandler(callback: (url: string) => string): void {
    this.assertNotDisposed();
    this.inner.set_fetch_handler(callback);
  }

  // ── Lifecycle ──

  /** Reset the VM state (clear classes, functions, etc.) but keep the VFS. */
  reset(): void {
    this.assertNotDisposed();
    this.inner.reset();
  }

  /** Release all WASM resources. The instance cannot be used after this. */
  dispose(): void {
    if (!this.disposed) {
      this.inner.free();
      this.disposed = true;
    }
  }

  /** PHP version string. */
  get version(): string {
    this.assertNotDisposed();
    return this.inner.php_version();
  }

  /** List of loaded extensions. */
  get extensions(): string[] {
    this.assertNotDisposed();
    return JSON.parse(this.inner.loaded_extensions());
  }

  private assertNotDisposed(): void {
    if (this.disposed) {
      throw new Error("PHP instance has been disposed");
    }
  }
}
