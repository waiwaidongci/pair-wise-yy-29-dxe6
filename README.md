# 数字凭证签发、验证和撤销服务

标准库 Python 3.11+ 实现，使用 SQLite 保存密钥版本、模板、凭证、争议、核验凭条和审计记录。服务支持最少字段披露、离线签名的在线撤销复核、密钥轮换和证件状态争议。

## 模块划分

- `app.py`：页面入口，HTTP 路由与静态页面。
- `receipts.py`：凭条处理，核验凭条的签发与一次性消费。
- `store.py`：持久化记录，SQLite 表结构、连接与审计日志。
- `services.py`：凭证业务，签发、出示、验证、撤销与争议。

## 初始化与启动

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8211`，也可使用 `--port` 与 `--db` 覆盖端口和数据库路径。身份使用 `X-Actor`、`X-Role` 请求头，角色为 `issuer`、`holder` 或 `regulator`；受理方消费凭条只需提供 `X-Actor`。

## 主要接口

- `POST /api/keys/rotate`：签发方轮换密钥。
- `POST /api/templates`：创建凭证模板。
- `POST /api/credentials`：签发凭证，支持幂等键。
- `POST /api/credentials/{id}/present`：按持有人选择披露字段并生成令牌，同时签发一张带过期时间的核验凭条（默认 300 秒，可用 `ttl_seconds` 调整，最长 3600 秒），凭条只携带本次披露的字段。
- `POST /api/receipts/{receipt_id}/consume`：受理方消费凭条。成功返回 `consumed` 并写入消费记录；凭条过期、凭证被撤销、凭条已消费或凭证处于争议中时，分别返回 `expired`、`revoked`、`used`、`disputed`，且不生成新的有效记录。可传 `at` 指定核验时间。
- `POST /api/verify`：验证令牌，可指定验证时间与在线/离线模式。
- `POST /api/credentials/{id}/revoke`：签发方撤销凭证。
- `POST /api/credentials/{id}/dispute`、`POST /api/disputes/{id}/resolve`：提出和处理撤销争议。
- `GET /api/state`、`GET /api/health`：查看状态（含凭条与消费记录）和健康检查。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

这是本地原型：私钥保存在 SQLite 中，离线验证只能依赖令牌内的到期时间，真实撤销仍需在线检查；也未实现可验证凭证联盟标准或硬件密钥保护。
