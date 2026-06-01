#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { DEFAULT_COVER, ROOT, POSTS_DIR, assertSafeOutputDir, ensureDir, parseArgs, prependFrontmatter, resolveCoverImage, slugify, writeText } from "./post-utils.js";

const { args, flags } = parseArgs(process.argv.slice(2));

if (flags.has("help") || args.length < 1) {
	console.log(`用法:
  pnpm import-pdf-post <PDF路径> [--slug yuwangbei-pdf] [--title 标题] [--category WriteUp] [--tags CTF,WriteUp,PDF] [--description 摘要] [--force]

示例:
  pnpm import-pdf-post "C:\\Users\\35159\\Downloads\\御网杯.pdf" --slug yuwangbei-pdf --title "御网杯 WriteUp PDF版"
`);
	process.exit(flags.has("help") ? 0 : 1);
}

const pdfPath = path.resolve(args[0]);
if (!fs.existsSync(pdfPath)) throw new Error(`PDF 不存在: ${pdfPath}`);
if (path.extname(pdfPath).toLowerCase() !== ".pdf") throw new Error(`不是 PDF 文件: ${pdfPath}`);

const fallbackTitle = path.basename(pdfPath, path.extname(pdfPath));
const title = String(flags.get("title") || `${fallbackTitle} PDF版`);
const slugFlag = flags.get("slug");
if (slugFlag === true) throw new Error("--slug 后面必须跟路径名,例如: --slug yuwangbei-pdf");
const slug = String(slugFlag || slugify(title));
const force = flags.get("force") === true;

const postDir = path.join(POSTS_DIR, slug);
assertSafeOutputDir(postDir, force);

const filesDir = path.join(ROOT, "public", "files");
ensureDir(filesDir);
const pdfName = `${slug}.pdf`;
const publicPdfPath = path.join(filesDir, pdfName);
fs.copyFileSync(pdfPath, publicPdfPath);

const publicUrl = `/files/${pdfName}`;
const coverImage = resolveCoverImage(flags, slug, "", DEFAULT_COVER);
const markdownBody = `# ${title}\n\n> 如果页面内嵌预览加载较慢，可以直接下载 PDF 阅读。\n\n[下载 PDF](${publicUrl})\n\n<iframe src="${publicUrl}" width="100%" height="850px" style="border: 1px solid rgba(255,255,255,0.12); border-radius: 12px; background: #111;"></iframe>\n`;

const markdown = prependFrontmatter(markdownBody, {
	title,
	description: String(flags.get("description") || `${title} PDF 归档`),
	image: coverImage,
	tags: String(flags.get("tags") || "PDF").split(",").map((s) => s.trim()).filter(Boolean),
	category: String(flags.get("category") || "归档"),
});

writeText(path.join(postDir, "index.md"), markdown);

console.log(`导入完成: ${path.relative(process.cwd(), postDir)}`);
console.log(`PDF: ${path.relative(process.cwd(), publicPdfPath)}`);
console.log(`标题: ${title}`);
console.log(`Slug: ${slug}`);
console.log(`封面: ${coverImage}`);
console.log(`预览地址: http://localhost:4321/posts/${slug}/`);
