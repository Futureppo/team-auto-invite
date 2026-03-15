# ChatGPT Team Auto Invite

一个轻量级的 ChatGPT Team 席位自动邀请工具，支持 Docker 一键部署。

### 环境变量

创建 `.env` 文件：

```env
JWT_TOKEN=your-team-jwt-token
ADMIN_PASSWORD=change-this-password
PORT=8080
RATE_LIMIT_SECONDS=180
```

`JWT_TOKEN` 仅作为首次启动时的初始 token 导入源，后续 token 管理通过后台完成。

### Docker Compose

```bash
git clone https://github.com/Futureppo/team-auto-invite
cd team-auto-invite
docker compose up -d
```

### Docker

```bash
git clone https://github.com/Futureppo/team-auto-invite
cd team-auto-invite
docker build -t team-auto-invite .
docker run -d -p 8080:8080 -v "$(pwd)/data:/app/data" --env-file .env team-auto-invite
```

### 管理后台

- 公开首页只保留邀请表单和后台入口按钮
- 管理后台路径为 `/admin`
- token 与冷却状态保存在 `data/state.json`
- 生产环境公开接口不会暴露 token 池和内部运行细节

## License

AGPLv3
