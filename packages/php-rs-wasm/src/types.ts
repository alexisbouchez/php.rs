/** Configuration for the PHP runtime. */
export interface PhpConfig {
  /** PHP INI settings (key-value pairs). */
  ini?: Record<string, string>;
  /** Environment variables accessible via getenv(). */
  env?: Record<string, string>;
  /** Enable persistent mode (functions/classes survive across eval calls). */
  persistent?: boolean;
}

/** Represents an HTTP-like request to pass to PHP. */
export interface PhpRequest {
  /** HTTP method (GET, POST, etc.). */
  method?: string;
  /** Request URL (used for $_SERVER['REQUEST_URI'] and $_GET parsing). */
  url?: string;
  /** Request headers as key-value pairs. */
  headers?: Record<string, string>;
  /** Request body (for POST/PUT). */
  body?: string;
}

/** Structured response from PHP execution. */
export interface PhpResponse {
  /** Script output (stdout). */
  output: string;
  /** Response headers set by header() calls. */
  headers: string[];
  /** HTTP status code (200 if not set). */
  statusCode: number;
}

/** Structured PHP error. */
export interface PhpError {
  /** Error kind (FatalError, TypeError, ParseError, etc.). */
  kind: string;
  /** Error message. */
  message: string;
  /** Source file. */
  file: string;
  /** Line number. */
  line: number;
}

/** A PHP token from the tokenizer. */
export interface Token {
  /** Token type (e.g. "T_STRING", "T_VARIABLE"). */
  type: string;
  /** Token text value. */
  value: string;
  /** Start byte offset. */
  start: number;
  /** End byte offset. */
  end: number;
  /** Line number (1-indexed). */
  line: number;
  /** Column number (1-indexed). */
  col: number;
}
