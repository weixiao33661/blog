#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import {
	POSTS_DIR,
	DEFAULT_COVER,
	assertSafeOutputDir,
	cleanFeishuMarkdown,
	inferTitle,
	parseArgs,
	prependFrontmatter,
	readText,
	resolveCoverImage,
	replaceFeishuImages,
	slugify,
	stripLeadingH1,
	writeText,
} from "./post-utils.js";

const { args, flags } = parseArgs(process.argv.slice(2));

if (flags.has("help") || args.length < 2) {
	console.log(`用法:
  pnpm import-feishu-wp <飞书导出.md> <飞书导出.pdf> [--slug litctf-2026] [--title 标题] [--category WriteUp] [--tags CTF,WriteUp,Web] [--description 摘要] [--force]

示例:
  pnpm import-feishu-wp "C:\\Users\\35159\\Downloads\\LitCTF2026.md" "C:\\Users\\35159\\Downloads\\LitCTF2026.pdf" --slug litctf-2026 --force
`);
	process.exit(flags.has("help") ? 0 : 1);
}

const mdPath = path.resolve(args[0]);
const pdfPath = path.resolve(args[1]);
const force = flags.get("force") === true;

let markdown = readText(mdPath);
const fallbackTitle = path.basename(mdPath, path.extname(mdPath));
const title = String(flags.get("title") || inferTitle(markdown, fallbackTitle));
const slugFlag = flags.get("slug");
if (slugFlag === true) throw new Error("--slug 后面必须跟路径名,例如: --slug yuwangbei");
const slug = String(slugFlag || slugify(title));
const postDir = path.join(POSTS_DIR, slug);
const imagesDir = path.join(postDir, "images");

assertSafeOutputDir(postDir, force);
fs.mkdirSync(imagesDir, { recursive: true });

const imageCount = extractPdfImages(pdfPath, imagesDir);
const replaced = replaceFeishuImages(markdown, imageCount);
markdown = replaced.markdown;
markdown = cleanFeishuMarkdown(markdown);
const coverImage = resolveCoverImage(flags, slug, markdown, replaced.count > 0 ? "./images/img-01.png" : DEFAULT_COVER);
markdown = stripLeadingH1(markdown, title);
markdown = prependFrontmatter(markdown, {
	title,
	description: String(flags.get("description") || `${title} CTF WriteUp`),
	image: coverImage,
	tags: String(flags.get("tags") || "CTF,WriteUp").split(",").map((s) => s.trim()).filter(Boolean),
	category: String(flags.get("category") || "WriteUp"),
});

const remainingFeishu = markdown.includes("feishu.cn");
if (remainingFeishu) throw new Error("清洗后仍存在 feishu.cn 链接,请检查 Markdown 中是否还有未识别图片链接");

writeText(path.join(postDir, "index.md"), markdown);

console.log(`导入完成: ${path.relative(process.cwd(), postDir)}`);
console.log(`标题: ${title}`);
console.log(`Slug: ${slug}`);
console.log(`封面: ${coverImage}`);
console.log(`图片: PDF 提取 ${imageCount} 张,Markdown 替换 ${replaced.count} 处`);
console.log(`预览地址: http://localhost:4321/posts/${slug}/`);

function extractPdfImages(pdf, outDir) {
	const py = path.join(os.tmpdir(), `extract-pdf-images-${Date.now()}.py`);
	fs.writeFileSync(py, `
import os, sys
try:
    import fitz
except Exception as e:
    print('需要 Python 包 PyMuPDF: pip install pymupdf', file=sys.stderr)
    raise
pdf = sys.argv[1]
out_dir = sys.argv[2]
os.makedirs(out_dir, exist_ok=True)
doc = fitz.open(pdf)
idx = 0
for page in doc:
    for img_info in page.get_images(full=True):
        xref = img_info[0]
        idx += 1
        pix = fitz.Pixmap(doc, xref)
        if pix.n - pix.alpha >= 4:
            pix = fitz.Pixmap(fitz.csRGB, pix)
        pix.save(os.path.join(out_dir, f'img-{idx:02d}.png'))
        pix = None
print(idx)
`, "utf8");
	try {
		const output = execFileSync("python", [py, pdf, outDir], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] }).trim();
		const count = Number(output.split(/\s+/).pop());
		if (!Number.isInteger(count) || count <= 0) throw new Error(`PDF 图片提取失败,输出: ${output}`);
		return count;
	} finally {
		fs.rmSync(py, { force: true });
	}
}
