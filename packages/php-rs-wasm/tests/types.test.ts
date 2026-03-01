import { describe, it, expect } from "vitest";
import type {
  PhpConfig,
  PhpRequest,
  PhpResponse,
  PhpError,
  Token,
} from "../src/types.js";

describe("TypeScript type definitions", () => {
  it("PhpConfig accepts valid config", () => {
    const config: PhpConfig = {
      ini: { display_errors: "0", memory_limit: "128M" },
      env: { APP_KEY: "secret" },
      persistent: true,
    };
    expect(config.ini?.display_errors).toBe("0");
    expect(config.persistent).toBe(true);
  });

  it("PhpConfig is optional", () => {
    const config: PhpConfig = {};
    expect(config.ini).toBeUndefined();
  });

  it("PhpRequest represents HTTP requests", () => {
    const req: PhpRequest = {
      method: "POST",
      url: "/api/users?page=1",
      headers: { "Content-Type": "application/json" },
      body: '{"name":"test"}',
    };
    expect(req.method).toBe("POST");
    expect(req.url).toContain("?page=1");
  });

  it("PhpResponse holds execution results", () => {
    const res: PhpResponse = {
      output: "<h1>Hello</h1>",
      headers: ["Content-Type: text/html"],
      statusCode: 200,
    };
    expect(res.statusCode).toBe(200);
    expect(res.headers).toHaveLength(1);
  });

  it("PhpError represents structured errors", () => {
    const err: PhpError = {
      kind: "FatalError",
      message: "Call to undefined function foo()",
      file: "/app/index.php",
      line: 42,
    };
    expect(err.kind).toBe("FatalError");
    expect(err.line).toBe(42);
  });

  it("Token represents lexer output", () => {
    const token: Token = {
      type: "T_STRING",
      value: "echo",
      start: 6,
      end: 10,
      line: 1,
      col: 7,
    };
    expect(token.type).toBe("T_STRING");
    expect(token.end - token.start).toBe(4);
  });
});
