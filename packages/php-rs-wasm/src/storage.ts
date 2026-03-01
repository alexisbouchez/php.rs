/**
 * Storage adapter interface for persisting VFS and session data.
 *
 * Implementations can back this with IndexedDB (browser), Cloudflare KV,
 * Deno KV, or any other key-value store.
 */
export interface StorageAdapter {
  /** Read a value by key. Returns null if not found. */
  get(key: string): Promise<Uint8Array | null>;
  /** Write a value by key. */
  set(key: string, value: Uint8Array): Promise<void>;
  /** Delete a value by key. */
  delete(key: string): Promise<void>;
}

/**
 * In-memory storage adapter. Useful for testing.
 */
export class MemoryStorage implements StorageAdapter {
  private store = new Map<string, Uint8Array>();

  async get(key: string): Promise<Uint8Array | null> {
    return this.store.get(key) ?? null;
  }

  async set(key: string, value: Uint8Array): Promise<void> {
    this.store.set(key, new Uint8Array(value));
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
}

/**
 * IndexedDB-backed storage adapter for browser environments.
 *
 * Persists VFS files and session data across page reloads.
 *
 * ```ts
 * const storage = await IndexedDBStorage.open("php-rs-vfs");
 * const data = await storage.get("/var/www/index.php");
 * ```
 */
export class IndexedDBStorage implements StorageAdapter {
  private db: IDBDatabase;

  private constructor(db: IDBDatabase) {
    this.db = db;
  }

  /**
   * Open (or create) an IndexedDB database for storage.
   * @param name - Database name (default: "php-rs-storage")
   */
  static open(name = "php-rs-storage"): Promise<IndexedDBStorage> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 1);

      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains("files")) {
          db.createObjectStore("files");
        }
      };

      request.onsuccess = () => {
        resolve(new IndexedDBStorage(request.result));
      };

      request.onerror = () => {
        reject(new Error(`Failed to open IndexedDB: ${request.error?.message}`));
      };
    });
  }

  async get(key: string): Promise<Uint8Array | null> {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction("files", "readonly");
      const store = tx.objectStore("files");
      const req = store.get(key);
      req.onsuccess = () => {
        const result = req.result;
        if (result instanceof Uint8Array) {
          resolve(result);
        } else if (result instanceof ArrayBuffer) {
          resolve(new Uint8Array(result));
        } else {
          resolve(null);
        }
      };
      req.onerror = () => reject(new Error(`IndexedDB get failed: ${req.error?.message}`));
    });
  }

  async set(key: string, value: Uint8Array): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction("files", "readwrite");
      const store = tx.objectStore("files");
      const req = store.put(new Uint8Array(value), key);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(new Error(`IndexedDB set failed: ${req.error?.message}`));
    });
  }

  async delete(key: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction("files", "readwrite");
      const store = tx.objectStore("files");
      const req = store.delete(key);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(new Error(`IndexedDB delete failed: ${req.error?.message}`));
    });
  }

  /** Close the database connection. */
  close(): void {
    this.db.close();
  }
}

/**
 * Cloudflare Workers KV storage adapter.
 *
 * ```ts
 * const storage = new CloudflareKVStorage(env.PHP_KV);
 * ```
 */
export class CloudflareKVStorage implements StorageAdapter {
  private kv: KVNamespace;

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  async get(key: string): Promise<Uint8Array | null> {
    const buf = await this.kv.get(key, "arrayBuffer");
    return buf ? new Uint8Array(buf) : null;
  }

  async set(key: string, value: Uint8Array): Promise<void> {
    await this.kv.put(key, value.buffer);
  }

  async delete(key: string): Promise<void> {
    await this.kv.delete(key);
  }
}

/** Cloudflare Workers KV namespace interface (minimal). */
interface KVNamespace {
  get(key: string, type: "arrayBuffer"): Promise<ArrayBuffer | null>;
  put(key: string, value: ArrayBuffer): Promise<void>;
  delete(key: string): Promise<void>;
}

/**
 * Deno KV storage adapter.
 *
 * ```ts
 * const kv = await Deno.openKv();
 * const storage = new DenoKVStorage(kv);
 * ```
 */
export class DenoKVStorage implements StorageAdapter {
  private kv: DenoKv;
  private prefix: string[];

  constructor(kv: DenoKv, prefix: string[] = ["php-rs"]) {
    this.kv = kv;
    this.prefix = prefix;
  }

  async get(key: string): Promise<Uint8Array | null> {
    const result = await this.kv.get<Uint8Array>([...this.prefix, key]);
    return result.value ?? null;
  }

  async set(key: string, value: Uint8Array): Promise<void> {
    await this.kv.set([...this.prefix, key], new Uint8Array(value));
  }

  async delete(key: string): Promise<void> {
    await this.kv.delete([...this.prefix, key]);
  }
}

/** Deno KV interface (minimal). */
interface DenoKv {
  get<T>(key: unknown[]): Promise<{ value: T | null }>;
  set(key: unknown[], value: unknown): Promise<void>;
  delete(key: unknown[]): Promise<void>;
}

/**
 * Session handler interface for PHP session bridge.
 *
 * Implement this to back `session_start()`/`$_SESSION` with a custom store.
 */
export interface SessionHandler {
  /** Read session data by session ID. Returns serialized session string or empty. */
  read(sessionId: string): Promise<string>;
  /** Write session data for a session ID. */
  write(sessionId: string, data: string): Promise<void>;
  /** Destroy a session. */
  destroy(sessionId: string): Promise<void>;
}

/**
 * Storage-backed session handler.
 *
 * Uses a `StorageAdapter` to persist PHP sessions.
 *
 * ```ts
 * const storage = await IndexedDBStorage.open();
 * const sessions = new StorageSessionHandler(storage);
 * // Wire into PHP via session bridge
 * ```
 */
export class StorageSessionHandler implements SessionHandler {
  private storage: StorageAdapter;
  private prefix: string;

  constructor(storage: StorageAdapter, prefix = "sess_") {
    this.storage = storage;
    this.prefix = prefix;
  }

  async read(sessionId: string): Promise<string> {
    const data = await this.storage.get(this.prefix + sessionId);
    if (!data) return "";
    return new TextDecoder().decode(data);
  }

  async write(sessionId: string, data: string): Promise<void> {
    await this.storage.set(this.prefix + sessionId, new TextEncoder().encode(data));
  }

  async destroy(sessionId: string): Promise<void> {
    await this.storage.delete(this.prefix + sessionId);
  }
}
