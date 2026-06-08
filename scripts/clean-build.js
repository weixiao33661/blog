import { existsSync, rmSync } from "node:fs";
import { resolve } from "node:path";

const targets = [".astro", "node_modules/.astro", "dist"];

for (const target of targets) {
	const fullPath = resolve(process.cwd(), target);
	if (!existsSync(fullPath)) continue;
	rmSync(fullPath, { recursive: true, force: true });
	console.log(`[clean-build] removed ${target}`);
}
