# ONE PIECE 航海日志 ⚓

> 我是要成为海贼王的男人。

[weixiao](https://github.com/) 的个人博客，主题为海贼王 (One Piece)。基于 [Astro](https://astro.build) 与 [Fuwari](https://github.com/saicaca/fuwari) 主题深度定制。

## 站点特色

- 顶部 3 图自动轮播 (5 秒切换 + 手动翻页)
- 全站固定通缉令背景 + 双层渐变遮罩
- 文章卡片半透明毛玻璃，正文配草帽红描边图框
- 友链页参考 bx33661 风格，分博客与组织两组
- 暗黑模式默认开启 (海贼王素材色彩浓，深色更协调)

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
├─ assets/onepiece/      # 海贼王素材 (背景、轮播图、头像)
├─ assets/friends/       # 友链头像
├─ components/
│  └─ BannerCarousel.astro   # 顶部轮播组件
├─ content/
│  ├─ posts/             # 博客文章 (Markdown)
│  └─ spec/about.md      # 关于页内容
├─ data/friends.ts       # 友链数据
├─ layouts/
│  └─ Layout.astro       # 注入背景层 + 主题 CSS 变量
├─ pages/
│  └─ friends.astro      # 友链页
└─ config.ts             # 站点全局配置
```

## 主题色变量

视觉调整集中在 `src/layouts/Layout.astro` 顶部的 `:root`：

```css
--op-bg-opacity        背景图本身透明度
--op-overlay-bot       底部遮罩深度
--op-card-bg-dark      暗色卡片不透明度
--op-card-blur         毛玻璃模糊半径
--op-accent            草帽红主色
```

## 致谢

- [Astro](https://astro.build) — Web framework
- [Fuwari](https://github.com/saicaca/fuwari) — 原始博客主题 (MIT)
- 海贼王 (ONE PIECE) © 尾田荣一郎 / 集英社 / 东映动画 — 角色设定版权归原作者所有，本站仅作个人爱好展示

## License

代码部分基于 Fuwari 的 MIT 许可证。文章内容未经允许请勿转载。
