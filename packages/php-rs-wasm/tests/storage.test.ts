import { describe, it, expect } from "vitest";
import { MemoryStorage, StorageSessionHandler } from "../src/storage.js";

describe("MemoryStorage", () => {
  it("returns null for missing keys", async () => {
    const storage = new MemoryStorage();
    expect(await storage.get("nope")).toBeNull();
  });

  it("stores and retrieves data", async () => {
    const storage = new MemoryStorage();
    const data = new TextEncoder().encode("hello");
    await storage.set("key", data);
    const result = await storage.get("key");
    expect(result).not.toBeNull();
    expect(new TextDecoder().decode(result!)).toBe("hello");
  });

  it("deletes data", async () => {
    const storage = new MemoryStorage();
    await storage.set("key", new Uint8Array([1, 2, 3]));
    await storage.delete("key");
    expect(await storage.get("key")).toBeNull();
  });

  it("stores a copy (does not share references)", async () => {
    const storage = new MemoryStorage();
    const data = new Uint8Array([1, 2, 3]);
    await storage.set("key", data);
    data[0] = 99;
    const result = await storage.get("key");
    expect(result![0]).toBe(1);
  });
});

describe("StorageSessionHandler", () => {
  it("returns empty string for missing sessions", async () => {
    const storage = new MemoryStorage();
    const handler = new StorageSessionHandler(storage);
    expect(await handler.read("nonexistent")).toBe("");
  });

  it("writes and reads session data", async () => {
    const storage = new MemoryStorage();
    const handler = new StorageSessionHandler(storage);
    await handler.write("abc123", 'user|s:4:"test";');
    expect(await handler.read("abc123")).toBe('user|s:4:"test";');
  });

  it("destroys session data", async () => {
    const storage = new MemoryStorage();
    const handler = new StorageSessionHandler(storage);
    await handler.write("abc123", "data");
    await handler.destroy("abc123");
    expect(await handler.read("abc123")).toBe("");
  });

  it("uses custom prefix", async () => {
    const storage = new MemoryStorage();
    const handler = new StorageSessionHandler(storage, "my_sess_");
    await handler.write("id1", "data");
    // Verify the key in storage uses the prefix
    expect(await storage.get("my_sess_id1")).not.toBeNull();
    expect(await storage.get("sess_id1")).toBeNull();
  });
});
