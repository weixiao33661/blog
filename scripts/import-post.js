#!/usr/bin/env node
import path from "node:path";
import {
	POSTS_DIR,
	assertSafeOutputDir,
	cleanFeishuMarkdown,
	copySiblingAssets,
	inferTitle,
	parseArgs,
	prependFrontmatter,
	readText,
	resolveCoverImage,
	slugify,
	stripLeadingH1,
	writeText,
} from "./post-utils.js";

const { args, flags } = parseArgs(process.argv.slice(2));

if (flags.has("help") || args.length < 1) {
	console.log(`用法:
  pnpm import-post <markdown路径> [--slug litctf-2026] [--title 标题] [--category 分类] [--tags 标签1,标签2] [--description 摘要] [--force]

示例:
  pnpm import-post "C:\\Users\\35159\\Downloads\\我的文章.md"
  pnpm import-post "C:\\Users\\35159\\Downloads\\我的文章.md" --slug my-post --tags 日常,笔记 --category 随笔
`);
	process.exit(flags.has("help") ? 0 : 1);
}

const mdPath = path.resolve(args[0]);
const force = flags.get("force") === true;
let markdown = readText(mdPath);

const fallbackTitle = path.basename(mdPath, path.extname(mdPath));
const title = String(flags.get("title") || inferTitle(markdown, fallbackTitle));
const slugFlag = flags.get("slug");
if (slugFlag === true) throw new Error("--slug 后面必须跟路径名,例如: --slug yuwangbei");
const slug = String(slugFlag || slugify(title));
const postDir = path.join(POSTS_DIR, slug);

assertSafeOutputDir(postDir, force);

markdown = cleanFeishuMarkdown(markdown);
const coverImage = resolveCoverImage(flags, slug, markdown);
markdown = stripLeadingH1(markdown, title);
markdown = prependFrontmatter(markdown, {
	title,
	description: String(flags.get("description") || ""),
	image: coverImage,
	tags: String(flags.get("tags") || "随笔").split(",").map((s) => s.trim()).filter(Boolean),
	category: String(flags.get("category") || "随笔"),
});

writeText(path.join(postDir, "index.md"), markdown);
const copied = copySiblingAssets(mdPath, postDir);

console.log(`导入完成: ${path.relative(process.cwd(), postDir)}`);
console.log(`标题: ${title}`);
console.log(`Slug: ${slug}`);
console.log(`封面: ${coverImage}`);
if (copied.length > 0) {
	console.log("复制图片/资源目录:");
	for (const item of copied) console.log(`- ${item.from} -> ${item.to}`);
}
console.log(`预览地址: http://localhost:4321/posts/${slug}/`);
