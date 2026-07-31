# OpenField Admin Panel

基于 Python + Flask 的管理面板,直连 OpenField 服务端共享的 PostgreSQL 数据库,
用于管理用户、角色、帖子与附件。

## 功能

- 独立账号密码登录(与主应用用户体系分离)
- 仪表盘:用户/帖子/消息/附件统计
- 用户管理:搜索、新建用户(用户名+昵称+密码)、设置角色(普通/管理员)、删除
- 帖子管理:列表、删除
- 附件管理:列表、预览、删除
- 支持为本地账号设置密码,预留账密登录(主应用 `POST /auth/login`);不支持自助注册

## 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 创建首个管理员账号(脚本交互式输入)
python seed_admin.py

# 3. 启动
python app.py        # 默认 http://127.0.0.1:5001
```

Windows 可直接运行 `scripts/start.bat`,Linux/macOS 运行 `scripts/start.sh`。

## 配置(环境变量)

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ADMIN_DB_HOST` | `localhost` | PostgreSQL 主机 |
| `ADMIN_DB_PORT` | `5432` | PostgreSQL 端口 |
| `ADMIN_DB_USER` | `of-user` | 数据库用户 |
| `ADMIN_DB_PASSWORD` | `of-user-1207` | 数据库密码 |
| `ADMIN_DB_NAME` | `openfield` | 数据库名 |
| `ADMIN_SECRET_KEY` | `admin-panel-secret-key-change-me` | Flask session 密钥 |

## 与主服务端的交互

- 面板直接读写共享 PostgreSQL,无需经过 Go 服务端 API。
- 新建用户的密码使用 bcrypt 哈希存储到 `users.password_hash`,与 Go 服务端
  `POST /api/v1/auth/login` 的校验兼容。
- 附件删除仅删除数据库记录与主应用引用;RustFS 中实际对象需通过 S3 工具清理。
