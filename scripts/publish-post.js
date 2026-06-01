#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { parseArgs } from "./post-utils.js";

const { args, flags } = parseArgs(process.argv.slice(2));

if (flags.has("help") || args.length < 1) {
	console.log(`用法:
  pnpm publish-post "post: 发布文章标题" [--skip-build]

示例:
  pnpm publish-post "post: 发布 LitCTF 2026 wp"
`);
	process.exit(flags.has("help") ? 0 : 1);
}

const message = args.join(" ").trim();
if (!message) throw new Error("commit message 不能为空");

run("git", ["status", "--short"], { capture: true });

if (!flags.has("skip-build")) {
	console.log("\n==> pnpm build");
	run("pnpm", ["build"]);
}

const status = run("git", ["status", "--short"], { capture: true }).trim();
if (!status) {
	console.log("没有需要提交的改动。");
	process.exit(0);
}

console.log("\n==> git add .");
run("git", ["add", "."]);

console.log("\n==> git commit");
run("git", ["commit", "-m", message]);

console.log("\n==> git push");
run("git", ["push"]);

console.log("\n发布完成。Cloudflare Pages 会自动部署,通常 1~2 分钟生效。");

function run(cmd, args, options = {}) {
	try {
		const output = execFileSync(cmd, args, {
			encoding: "utf8",
			stdio: options.capture ? ["ignore", "pipe", "pipe"] : "inherit",
		});
		if (options.capture && output) process.stdout.write(output);
		return output ?? "";
	} catch (error) {
		if (options.capture) {
			if (error.stdout) process.stdout.write(error.stdout.toString());
			if (error.stderr) process.stderr.write(error.stderr.toString());
		}
		process.exit(error.status || 1);
	}
}
