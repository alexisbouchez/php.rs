# Ralph Loop Iteration

You are running inside an autonomous TDD loop. No human is present. Work precisely.

## Your task this iteration

1. **Read `TODO.txt`** — find the FIRST line matching `[ ]` (not started). That is your task.
2. **If the task has sub-items** (indented `[ ]` under it), work on the first unchecked sub-item.
3. **Do the work using TDD**:
   - Write a failing test FIRST (Red)
   - Write the minimum code to make it pass (Green)
   - Refactor if needed while tests stay green
   - Run `cargo test` to verify
4. **Update `TODO.txt`**: change `[ ]` to `[x]` for completed items, `[~]` for partially done parents.
5. **Run `cargo test` one final time** to confirm everything passes.
6. **Output your status on the VERY LAST line**, exactly one of:
   - `RALPH_OK` — task completed, tests pass, TODO.txt updated
   - `RALPH_FAIL` — tests failing, could not fix
   - `RALPH_BLOCKED` — cannot proceed (missing dependency, unclear requirement)
   - `RALPH_DONE` — no more `[ ]` items in TODO.txt, project complete

## Rules

- Work ONLY on the current task. Do not skip ahead.
- If Phase 0 scaffolding isn't done yet, do that first (create Cargo workspace, crate stubs, etc.)
- Every file you create MUST have tests.
- Keep changes small and focused — one TODO item per iteration.
- If `cargo test` fails after your changes, fix it before finishing.
- Always `cargo fmt --all` and `cargo clippy --all-targets` before finishing.
- Commit after each completed item: `git add -A && git commit -m "[$PHASE.$ITEM] description"`
- Do NOT ask questions. Make reasonable decisions and move forward.
- Do NOT output anything after your status line.
