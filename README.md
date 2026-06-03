# weixiao Security Lab

Android 逆向、CTF WriteUp 与网络安全学习笔记。

[weixiao](https://github.com/) 的个人博客。基于 [Astro](https://astro.build) 与 [Fuwari](https://github.com/saicaca/fuwari) 主题定制，当前视觉定位为网络安全研究笔记。

## 站点特色

- 顶部 5 图自动轮播 (5 秒切换 + 手动翻页)
- 深色安全研究风格背景，带低调网格与终端感视觉层
- 文章卡片使用安全报告式信息结构，突出分类、标签、日期与摘要
- 头像信息卡支持微信、QQ 二维码悬停预览
- 友链页参考 bx33661 风格，分博客与组织两组
- 保留明暗模式切换，默认跟随系统

## 本地开发

需要 Node.js ≥ 20 与 pnpm ≥ 9。

```bash
pnpm install         # 装依赖
pnpm dev             # 启动开发服务器  http://localhost:4321
pnpm build           # 生产构建到 dist/
pnpm new-post 标题   # 新建一篇文章
```

## 目录速览

```
src/
├─ assets/top-banners/   # 顶部轮播图
├─ assets/covers/        # 文章封面
├─ assets/friends/       # 友链头像
├─ assets/images/        # 站点头像等通用图片
├─ components/
│  └─ BannerCarousel.astro   # 顶部轮播组件
├─ content/
│  ├─ posts/             # 博客文章 (Markdown)
│  └─ spec/about.md      # 关于页内容
├─ data/friends.ts       # 友链数据
├─ layouts/
│  └─ Layout.astro       # 注入背景层 + 安全风格全局样式
├─ pages/
│  └─ friends.astro      # 友链页
└─ config.ts             # 站点全局配置
public/
└─ social/               # 微信、QQ 等公开二维码图片
```

## 个人信息与社交二维码

头像下方的个人信息由 `src/config.ts` 中的 `profileConfig` 控制。普通外链只需要配置 `name`、`icon`、`url`；微信、QQ 这类二维码入口额外配置 `qrCode`，图片放在 `public/social/`：

```ts
{
  name: "微信",
  icon: "fa6-brands:weixin",
  url: "/social/wechat.png",
  qrCode: "/social/wechat.png",
}
```

## 主题色变量

视觉调整主要集中在 `src/layouts/Layout.astro` 的安全背景层，以及 `src/styles/variables.styl` 的主题变量：

```css
--sec-card-bg-dark      暗色卡片背景
--sec-card-border-dark  暗色卡片边框
--sec-card-blur         毛玻璃模糊半径
--sec-accent            安全风格强调色
```

## 致谢

- [Astro](https://astro.build) — Web framework
- [Fuwari](https://github.com/saicaca/fuwari) — 原始博客主题 (MIT)

## License

代码部分基于 Fuwari 的 MIT 许可证。文章内容未经允许请勿转载。
