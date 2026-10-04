# OpenField Admin Panel

基于 Python + Flask 的管理面板,直连 OpenField 服务端共享的 PostgreSQL 数据库,
用于管理用户、角色、帖子与附件。

## 功能

- 独立账号密码登录(与主应用用户体系分离)
- 仪表盘:用户/帖子/消息/附件统计
- 用户管理:搜索、新建用户(用户名+昵称+密码)、设置角色(普通/管理员)、重置密码、删除
- 帖子管理:列表、删除
- 附件管理:列表、预览、删除
- 支持为本地账号设置密码,预留账密登录(主应用 `POST /auth/login`);不支持自助注册
- 界面基于本地 Bootstrap 5 + Bootstrap Icons(`static/` 目录),无需外网即可加载

## 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 创建首个管理员账号(脚本交互式输入)
python seed_admin.py

# 3. 启动
python app.py        # 默认 http://127.0.0.1:1343
```

Windows 可直接运行 `scripts/start.bat`,Linux/macOS 运行 `scripts/start.sh`。

## 配置(环境变量)

数据库与对象存储的凭据**没有内置默认值**:必须显式设置,否则启动即失败并提示
缺失的变量名。这是有意为之——早期版本把 `of-user` / `of-user-1207` /
`rustfsadmin` 写在代码里,而本仓库是公开的,忘记设置环境变量的部署会直接以
公开口令连接数据库。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ADMIN_DB_HOST` | `localhost` | PostgreSQL 主机 |
| `ADMIN_DB_PORT` | `5432` | PostgreSQL 端口 |
| `ADMIN_DB_USER` | *(必填)* | 数据库用户 |
| `ADMIN_DB_PASSWORD` | *(必填)* | 数据库密码 |
| `ADMIN_DB_NAME` | `openfield` | 数据库名 |
| `ADMIN_DB_SSLMODE` | *(留空)* | 留空时使用 libpq 默认值 `prefer`(优先 TLS)。生产环境请显式设为 `require` 或 `verify-full` |
| `RUSTFS_ENDPOINT` | `localhost:9000` | 对象存储地址;留空则禁用对象存储功能 |
| `RUSTFS_ACCESS_KEY` | *(设置了 ENDPOINT 时必填)* | 对象存储 Access Key |
| `RUSTFS_SECRET_KEY` | *(设置了 ENDPOINT 时必填)* | 对象存储 Secret Key |
| `ADMIN_SECRET_KEY` | *(留空)* | Flask session 签名密钥 |
| `ADMIN_COOKIE_SECURE` | `false` | 设为 `true` 时仅通过 HTTPS 发送会话 cookie |
| `ADMIN_TRUSTED_PROXY_COUNT` | `0` | 面板前面的可信反向代理层数,用于解析 `X-Forwarded-For` |

### 关于 `ADMIN_SECRET_KEY`

**不要把它设成一个固定字符串。** 会话签名密钥一旦被他人得知,任何人都可以伪造
`openfield_admin` 会话 cookie,完全绕过登录。

留空即可:面板会在首次启动时生成一个随机密钥并以 `0600` 权限写入同目录的
`.secret_key`(已在 `.gitignore` 中)。只有在你希望由外部密钥管理系统统一提供
密钥时才设置该变量,并且必须是一个足够长的高熵随机值。

> 历史文档曾把默认值写成 `admin-panel-secret-key-change-me`。代码中从未有过这个
> 默认值,照做反而会把会话密钥变成公开已知值——请不要这样做。

## 与主服务端的交互

- 面板直接读写共享 PostgreSQL,无需经过 Go 服务端 API。
- 新建用户的密码使用 bcrypt 哈希存储到 `users.password_hash`,与 Go 服务端
  `POST /api/v1/auth/login` 的校验兼容。
- 附件删除仅删除数据库记录与主应用引用;RustFS 中实际对象需通过 S3 工具清理。
