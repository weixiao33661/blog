import berial from "../assets/friends/berial.jpg";
import bx from "../assets/friends/bx.jpg";
import ewoji from "../assets/friends/ewoji.jpg";
import hnusec from "../assets/friends/hnusec.jpg";
import iam0range from "../assets/friends/iam0range.jpg";
import jatopos from "../assets/friends/jatopos.jpg";
import m1n9 from "../assets/friends/m1n9.jpg";
import manxiao from "../assets/friends/manxiao.jpg";
import orxiain from "../assets/friends/orxiain.jpg";
import q1uju from "../assets/friends/q1uju.jpg";
import raft from "../assets/friends/raft.jpg";
import tree from "../assets/friends/tree.jpg";
import unjoke from "../assets/friends/unjoke.jpg";

export interface Friend {
	name: string;
	url: string;
	avatar: ImageMetadata;
	bio?: string;
}

export const friends: Friend[] = [
	{ name: "Bx", url: "https://www.bx33661.com/", avatar: bx, bio: "BX 的安全研究小屋" },
	{ name: "orxiain", url: "https://orxiain.life/", avatar: orxiain, bio: "ORXIAIN. - ISLAND" },
	{ name: "Jatopos", url: "https://jatopos.github.io/", avatar: jatopos, bio: "Jatopos 的航海日志" },
	{ name: "Berial", url: "https://berial.cn/", avatar: berial, bio: "Berial's Blog" },
	{ name: "Ewoji", url: "https://ewoji.cn/", avatar: ewoji, bio: "Ewoji 的小破站" },
	{ name: "iam0range", url: "https://iam0range.github.io/", avatar: iam0range, bio: "iam0range 的笔记本" },
	{ name: "Unjoke", url: "https://unjoke.cn/", avatar: unjoke, bio: "Unjoke" },
	{ name: "m1n9", url: "https://mi1n9.github.io/", avatar: m1n9, bio: "m1n9 的安全博客" },
	{ name: "Raft", url: "https://floatingraft.github.io/", avatar: raft, bio: "Floating Raft" },
	{ name: "Tree", url: "https://treesec.cn/", avatar: tree, bio: "Tree Security" },
	{ name: "Q1uJu", url: "https://q1uju.cc/", avatar: q1uju, bio: "Q1uJu 的小窝" },
	{ name: "漫宿骄盛", url: "https://www.cnblogs.com/msjs", avatar: manxiao, bio: "博客园 · 漫宿骄盛" },
];

export const orgs: Friend[] = [
	{ name: "HnuSec", url: "https://www.hnusec.com/", avatar: hnusec, bio: "我所在的安全组织" },
];
