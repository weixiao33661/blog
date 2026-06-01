import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
export const POSTS_DIR = path.join(ROOT, "src", "content", "posts");

export function ensureDir(dir) {
	fs.mkdirSync(dir, { recursive: true });
}

export function readText(file) {
	return fs.readFileSync(file, "utf8");
}

export function writeText(file, content) {
	ensureDir(path.dirname(file));
	fs.writeFileSync(file, content, "utf8");
}

export function copyFile(src, dest) {
	ensureDir(path.dirname(dest));
	fs.copyFileSync(src, dest);
}

export function pathExists(file) {
	return fs.existsSync(file);
}

export function slugify(input) {
	return String(input)
		.trim()
		.toLowerCase()
		.normalize("NFKD")
		.replace(/[̀-ͯ]/g, "")
		.replace(/[^a-z0-9一-龥]+/g, "-")
		.replace(/^-+|-+$/g, "") || `post-${Date.now()}`;
}

export function inferTitle(markdown, fallback) {
	const fm = markdown.match(/^---\n([\s\S]*?)\n---/);
	if (fm) {
		const title = fm[1].match(/^title:\s*["']?(.+?)["']?\s*$/m);
		if (title) return title[1].trim();
	}
	const h1 = markdown.match(/^#\s+(.+)$/m);
	return h1 ? h1[1].trim() : fallback;
}

export function stripLeadingH1(markdown, title) {
	const pattern = new RegExp(`^#\\s+${escapeRegExp(title)}\\s*\\n+`);
	return markdown.replace(pattern, "");
}

export function hasFrontmatter(markdown) {
	return /^---\n[\s\S]*?\n---\n/.test(markdown);
}

export function prependFrontmatter(markdown, options) {
	if (hasFrontmatter(markdown)) return markdown;
	const {
		title,
		description = "",
		published = new Date().toISOString().slice(0, 10),
		tags = ["随笔"],
		category = "随笔",
		draft = false,
		image = "",
	} = options;
	return `---\ntitle: ${yamlString(title)}\npublished: ${published}\ndescription: ${yamlString(description)}\nimage: ${yamlString(image)}\ntags: [${tags.map(yamlBare).join(", ")}]\ncategory: ${yamlString(category)}\ndraft: ${draft}\n---\n\n${markdown}`;
}

export function cleanFeishuMarkdown(markdown) {
	let out = markdown;
	out = unescapeOutsideCode(out);
	out = normalizeCodeFences(out);
	return out;
}

export function replaceFeishuImages(markdown, count) {
	const feishuPattern = /!\[Image\]\(https:\/\/internal-api-drive-stream\.feishu\.cn[^)]+\)/g;
	let i = 0;
	let out = markdown.replace(feishuPattern, () => {
		i += 1;
		return `![Figure ${i}](./images/img-${String(i).padStart(2, "0")}.png)`;
	});

	if (i === 0) {
		const genericImagePattern = /!\[[^\]\n]*\]\((?!\.\/images\/img-\d{2}\.png\))[^)\n]+\)/g;
		out = markdown.replace(genericImagePattern, () => {
			i += 1;
			return `![Figure ${i}](./images/img-${String(i).padStart(2, "0")}.png)`;
		});
	}

	if (typeof count === "number" && i !== count) {
		throw new Error(`图片数量不一致: Markdown 中有 ${i} 个图片占位,但 PDF 提取到 ${count} 张图`);
	}
	return { markdown: out, count: i };
}

export function normalizeCodeFences(markdown) {
	const mapping = new Map([
		["plain text", "text"],
		["plain", "text"],
		["plaintext", "text"],
		["bash", "bash"],
		["shell", "bash"],
		["python", "python"],
		["javascript", "js"],
		["go", "go"],
		["c", "c"],
		["sql", "sql"],
	]);
	return markdown.replace(/^```([A-Za-z][A-Za-z ]*)/gm, (_, lang) => {
		const normalized = mapping.get(lang.trim().toLowerCase()) ?? lang.trim().toLowerCase();
		return `\`\`\`${normalized}`;
	});
}

export function unescapeOutsideCode(markdown) {
	const parts = markdown.split(/(```[\s\S]*?```|`[^`\n]+`)/g);
	return parts.map((part) => {
		if (part.startsWith("`")) return part;
		let text = part;
		text = text.replace(/\\&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)));
		text = text.replace(/\\&#x([0-9a-fA-F]+);/g, (_, n) => String.fromCodePoint(parseInt(n, 16)));
		text = text.replace(/&\\#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)));
		text = text.replace(/&\\#x([0-9a-fA-F]+);/g, (_, n) => String.fromCodePoint(parseInt(n, 16)));
		text = text.replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)));
		text = text.replace(/&#x([0-9a-fA-F]+);/g, (_, n) => String.fromCodePoint(parseInt(n, 16)));
		text = text.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"');
		for (const char of "_-.()[]<>*~!+=?,;:/&{}\"'|") {
			text = text.replaceAll(`\\${char}`, char);
		}
		text = text.replaceAll("\\`", "`");
		return text;
	}).join("");
}

export function copySiblingAssets(markdownPath, postDir) {
	const mdDir = path.dirname(markdownPath);
	const copied = [];
	for (const name of ["images", "assets", "img"]) {
		const srcDir = path.join(mdDir, name);
		if (!pathExists(srcDir) || !fs.statSync(srcDir).isDirectory()) continue;
		const destDir = path.join(postDir, name === "img" ? "images" : name);
		copyDir(srcDir, destDir);
		copied.push({ from: srcDir, to: destDir });
	}
	return copied;
}

export function copyDir(src, dest) {
	ensureDir(dest);
	for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
		const from = path.join(src, entry.name);
		const to = path.join(dest, entry.name);
		if (entry.isDirectory()) copyDir(from, to);
		else fs.copyFileSync(from, to);
	}
}

export function assertSafeOutputDir(postDir, force = false) {
	if (pathExists(postDir)) {
		if (!force) throw new Error(`目标目录已存在: ${postDir}\n如果要覆盖,加 --force`);
		fs.rmSync(postDir, { recursive: true, force: true });
	}
	ensureDir(postDir);
}

export function yamlString(value) {
	const text = String(value ?? "");
	if (text === "") return "''";
	return JSON.stringify(text);
}

export function yamlBare(value) {
	return String(value).replace(/[\[\],]/g, "").trim();
}

export function escapeRegExp(value) {
	return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function parseArgs(argv) {
	const args = [];
	const flags = new Map();
	for (let i = 0; i < argv.length; i += 1) {
		const item = argv[i];
		if (!item.startsWith("--")) {
			args.push(item);
			continue;
		}
		const key = item.slice(2);
		const next = argv[i + 1];
		if (!next || next.startsWith("--")) {
			flags.set(key, true);
		} else {
			flags.set(key, next);
			i += 1;
		}
	}
	return { args, flags };
}
