/**
 * `<php-playground>` — Embeddable PHP playground Web Component.
 *
 * ```html
 * <script src="https://unpkg.com/php-rs-wasm/dist/esm/playground.js" type="module"></script>
 * <php-playground code="<?php echo 'Hello!';" theme="dark"></php-playground>
 * ```
 *
 * @module
 */

const TEMPLATE = `
<style>
  :host {
    display: block;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
    border: 1px solid var(--php-playground-border, #313244);
    border-radius: 8px;
    overflow: hidden;
    background: var(--php-playground-bg, #1e1e2e);
    color: var(--php-playground-fg, #cdd6f4);
  }
  .toolbar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    background: var(--php-playground-toolbar-bg, #181825);
    border-bottom: 1px solid var(--php-playground-border, #313244);
    font-size: 13px;
  }
  .toolbar .title {
    font-weight: 600;
    color: var(--php-playground-accent, #89b4fa);
  }
  .toolbar .title span { color: #f38ba8; }
  .btn {
    padding: 4px 12px;
    border: none;
    border-radius: 4px;
    font-size: 12px;
    cursor: pointer;
    font-weight: 500;
    background: var(--php-playground-btn-bg, #a6e3a1);
    color: var(--php-playground-btn-fg, #1e1e2e);
  }
  .btn:hover { opacity: 0.9; }
  .spacer { flex: 1; }
  .timing {
    font-size: 11px;
    color: #6c7086;
  }
  .editor {
    width: 100%;
    min-height: 120px;
    padding: 12px;
    background: var(--php-playground-bg, #1e1e2e);
    color: var(--php-playground-fg, #cdd6f4);
    border: none;
    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
    font-size: 14px;
    line-height: 1.6;
    resize: vertical;
    outline: none;
    tab-size: 4;
    box-sizing: border-box;
  }
  .output-bar {
    padding: 4px 12px;
    background: var(--php-playground-toolbar-bg, #181825);
    border-top: 1px solid var(--php-playground-border, #313244);
    font-size: 12px;
    color: #a6adc8;
  }
  .output {
    padding: 12px;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 13px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-break: break-all;
    min-height: 40px;
    max-height: 300px;
    overflow: auto;
  }
  .output.error { color: #f38ba8; }
</style>
<div class="toolbar">
  <span class="title">php<span>.rs</span></span>
  <div class="spacer"></div>
  <span class="timing" id="timing"></span>
  <button class="btn" id="run-btn">Run</button>
</div>
<textarea class="editor" id="editor" spellcheck="false"></textarea>
<div class="output-bar">Output</div>
<div class="output" id="output"></div>
`;

class PhpPlayground extends HTMLElement {
  private shadow: ShadowRoot;
  private editorEl!: HTMLTextAreaElement;
  private outputEl!: HTMLDivElement;
  private timingEl!: HTMLSpanElement;
  private runBtn!: HTMLButtonElement;
  private php: any = null;

  constructor() {
    super();
    this.shadow = this.attachShadow({ mode: "open" });
    this.shadow.innerHTML = TEMPLATE;
  }

  connectedCallback(): void {
    this.editorEl = this.shadow.getElementById("editor") as HTMLTextAreaElement;
    this.outputEl = this.shadow.getElementById("output") as HTMLDivElement;
    this.timingEl = this.shadow.getElementById("timing") as HTMLSpanElement;
    this.runBtn = this.shadow.getElementById("run-btn") as HTMLButtonElement;

    // Set initial code from attribute or slot
    const code = this.getAttribute("code") ?? '<?php echo "Hello from php.rs!";';
    this.editorEl.value = code;

    // Set height from attribute
    const height = this.getAttribute("editor-height");
    if (height) {
      this.editorEl.style.height = height;
    }

    // Keyboard shortcut
    this.editorEl.addEventListener("keydown", (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        this.run();
      }
      if (e.key === "Tab") {
        e.preventDefault();
        const start = this.editorEl.selectionStart;
        const end = this.editorEl.selectionEnd;
        this.editorEl.value =
          this.editorEl.value.substring(0, start) +
          "    " +
          this.editorEl.value.substring(end);
        this.editorEl.selectionStart = this.editorEl.selectionEnd = start + 4;
      }
    });

    this.runBtn.addEventListener("click", () => this.run());

    // Auto-initialize
    this.initPhp();
  }

  private async initPhp(): Promise<void> {
    try {
      // Import the PHP class from the package
      const { PHP } = await import("./php.js");
      await PHP.init();
      this.php = new PHP();
      this.runBtn.textContent = "Run";
    } catch (e) {
      this.outputEl.textContent = `Failed to load PHP runtime: ${e}`;
      this.outputEl.classList.add("error");
    }
  }

  private run(): void {
    if (!this.php) return;
    const code = this.editorEl.value;
    const start = performance.now();

    try {
      const result = this.php.run(code);
      const elapsed = (performance.now() - start).toFixed(1);
      this.timingEl.textContent = `${elapsed}ms`;
      this.outputEl.textContent = result.output;
      this.outputEl.classList.remove("error");
    } catch (e) {
      const elapsed = (performance.now() - start).toFixed(1);
      this.timingEl.textContent = `${elapsed}ms`;
      this.outputEl.textContent = `Error: ${e}`;
      this.outputEl.classList.add("error");
    }

    this.php.reset();
  }

  // Support attribute changes
  static get observedAttributes(): string[] {
    return ["code"];
  }

  attributeChangedCallback(name: string, _old: string, value: string): void {
    if (name === "code" && this.editorEl) {
      this.editorEl.value = value;
    }
  }
}

// Register the custom element
if (typeof customElements !== "undefined") {
  customElements.define("php-playground", PhpPlayground);
}

export { PhpPlayground };
