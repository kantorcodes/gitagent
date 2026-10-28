import { chmod, mkdtemp, readFile, writeFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { evaluateWithGuard, guardJsonObject, guardResponseToHookResult } from "../integrations/hol-guard/index.mjs";

describe("HOL Guard GitAgent integration", () => {
	it("fails closed when Node rejects the Guard argv synchronously", async () => {
		// An embedded NUL makes child_process.spawn throw before event handlers exist.
		// The hook must return an explicit block rather than reject its promise.
		const result = await evaluateWithGuard(
			{ tool: "cli", args: { command: "echo safe\u0000unsafe" } },
			{ binary: process.execPath, workspace: process.cwd(), timeout_ms: 1000 },
		);
		assert.deepEqual(result, {
			action: "block",
			reason: "HOL Guard could not start due to invalid process arguments.",
		});
	});

	it("refuses multiple structured Guard verdicts, including deny followed by allow", () => {
		const allow = JSON.stringify({ minimum_action: "allow", classification: { explicitly_benign: true } });
		const deny = JSON.stringify({ minimum_action: "block", classification: { explicitly_benign: false } });
		assert.deepEqual(guardJsonObject("diagnostic\n" + allow), JSON.parse(allow));
		for (const output of [deny + "\n" + allow, allow + "\n" + deny, allow + "\n" + allow]) {
			assert.equal(guardJsonObject(output), null);
		}
	});

	it("maps Guard command floors to GitAgent hook results", () => {
		assert.deepEqual(
			guardResponseToHookResult({
				minimum_action: "allow",
				classification: { explicitly_benign: true },
			}),
			{ action: "allow" },
		);
		assert.equal(
			guardResponseToHookResult({
				minimum_action: "allow",
				classification: { explicitly_benign: false },
			}).action,
			"block",
		);
		assert.equal(
			guardResponseToHookResult({
				minimum_action: "monitor",
				classification: { explicitly_benign: true },
			}).action,
			"block",
		);
		assert.deepEqual(
			guardResponseToHookResult({
				minimum_action: "review",
				classification: { reason: "Guard requires review" },
			}),
			{ action: "block", reason: "Guard requires review" },
		);
		assert.deepEqual(
			guardResponseToHookResult({
				decision: "review",
				minimum_action: "allow",
				classification: { explicitly_benign: true, reason: "Explicit review is required" },
			}),
			{ action: "block", reason: "Explicit review is required" },
		);
		assert.equal(
			guardResponseToHookResult({
				decision: "unrecognized-stop",
				minimum_action: "allow",
				classification: { explicitly_benign: true },
			}).action,
			"block",
		);
		assert.equal(
			guardResponseToHookResult({
				decision: "allow",
				minimum_action: "allow",
				classification: { explicitly_benign: true },
			}).action,
			"allow",
		);
		for (const stop of [
			{ continue: false },
			{ continue: "false" },
			{ continue: 0 },
			{ continue: null },
			{ decision: "deny" },
			{ decision: "review" },
			{ decision: 0 },
			{ policy_action: "block" },
			{ policy_action: "review" },
			{ policy_action: "warn" },
			{ policy_action: null },
			{ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny" } },
			{ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "ask" } },
			{ hookSpecificOutput: { hookEventName: "PostToolUse", permissionDecision: "allow" } },
			{ hookSpecificOutput: { permissionDecision: "allow" } },
			{ hookSpecificOutput: null },
		]) {
			assert.equal(
				guardResponseToHookResult({
					minimum_action: "allow",
					classification: { explicitly_benign: true },
					...stop,
				}).action,
				"block",
			);
		}
		assert.equal(guardResponseToHookResult({
			policy_action: "not_run",
			minimum_action: "allow",
			classification: { explicitly_benign: true },
		}).action, "allow");
		assert.equal(guardResponseToHookResult({
			policy_action: "not_run",
			minimum_action: "allow",
			classification: { explicitly_benign: true },
			hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow" },
		}).action, "allow");
		assert.equal(guardResponseToHookResult({ minimum_action: "block" }).action, "block");
		assert.equal(guardResponseToHookResult({ unexpected: true }).action, "block");
	});

	it("only gates the cli tool", async () => {
		assert.deepEqual(
			await evaluateWithGuard({ tool: "read", args: { path: "README.md" } }, { binary: "missing-guard" }),
			{ action: "allow" },
		);
	});

	it("blocks oversized Guard output even when followed by an allow verdict", async (t) => {
		if (process.platform === "win32") {
			t.skip("fixture executable uses a POSIX shebang");
			return;
		}
		const dir = await mkdtemp(join(tmpdir(), "gitagent-hol-guard-size-"));
		for (const stream of ["stdout", "stderr"]) {
			const fixture = join(dir, `oversized-${stream}.mjs`);
			await writeFile(
				fixture,
				`#!/usr/bin/env node\nprocess.${stream}.write("X".repeat(1024 * 1024 + 1));\nprocess.stdout.write(JSON.stringify({ minimum_action: "allow", classification: { explicitly_benign: true } }));\n`,
				"utf-8",
			);
			await chmod(fixture, 0o755);
			const result = await evaluateWithGuard(
				{ tool: "cli", args: { command: "git status" } },
				{ binary: fixture, workspace: dir, timeout_ms: 3000 },
			);
			assert.deepEqual(result, { action: "block", reason: "HOL Guard output exceeded the maximum size." });
		}
	});

	it("inspects the exact command text and blocks a review", async (t) => {
		if (process.platform === "win32") {
			t.skip("fixture executable uses a POSIX shebang");
			return;
		}

		const dir = await mkdtemp(join(tmpdir(), "gitagent-hol-guard-"));
		const capture = join(dir, "capture.json");
		const fixture = join(dir, "hol-guard-fixture.mjs");
		await writeFile(
			fixture,
			`#!/usr/bin/env node\nimport { writeFileSync } from "node:fs";\nwriteFileSync(process.env.GUARD_CAPTURE, JSON.stringify({ argv: process.argv.slice(2), cwd: process.cwd(), guardHome: process.env.HOL_GUARD_HOME, home: process.env.HOME }));\nprocess.stdout.write(JSON.stringify({ minimum_action: "review", classification: { reason: "Guard requires review" } }, null, 2) + "\\n");\n`,
			"utf-8",
		);
		await chmod(fixture, 0o755);

		const previous = process.env.GUARD_CAPTURE;
		process.env.GUARD_CAPTURE = capture;
		try {
			const result = await evaluateWithGuard(
				{ session_id: "session-1", tool: "cli", args: { command: "  cat <<\'EOF\'\\nexample\\nEOF\\n" } },
				{
					binary: fixture,
					workspace: dir,
					timeout_ms: 2000,
					guard_home: join(dir, "guard-home"),
					home: join(dir, "home"),
				},
			);
			assert.deepEqual(result, { action: "block", reason: "Guard requires review" });

			const recorded = JSON.parse(await readFile(capture, "utf-8"));
			assert.deepEqual(recorded.argv, ["command", "test", "--json", "--", "  cat <<\'EOF\'\\nexample\\nEOF\\n"]);
			assert.equal(recorded.cwd, dir);
			assert.equal(recorded.guardHome, join(dir, "guard-home"));
			assert.equal(recorded.home, join(dir, "home"));
		} finally {
			if (previous === undefined) delete process.env.GUARD_CAPTURE;
			else process.env.GUARD_CAPTURE = previous;
		}
	});
});
