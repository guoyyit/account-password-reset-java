# account-password-reset-java

本地可端到端运行的账户口令重置与恢复服务（Spring Boot 3 / Java 17 / H2 文件库）。
不依赖任何外部服务：重置凭据通过本地模拟渠道（outbox 目录 + 日志）投递。

## 运行与测试

```bash
mvn spring-boot:run   # 启动服务，默认端口 8080，数据落盘 ./data/
mvn test              # 运行全部自动化测试
```

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/auth/register` | 注册 `{username, password}`，口令经 BCrypt 不可逆存储 |
| POST | `/api/auth/login` | 登录 `{username, password}`，成功签发会话令牌 |
| POST | `/api/auth/logout` | 撤销当前会话（`Authorization: Bearer <token>`） |
| GET | `/api/auth/me` | 校验会话并返回当前账户名 |
| POST | `/api/reset/request` | 申请重置凭据 `{username}`，响应恒定，不泄露账户是否存在 |
| POST | `/api/reset/verify` | 校验凭据 `{username, code}`，只读不消耗 |
| POST | `/api/reset/confirm` | 凭据换新口令 `{username, code, newPassword}` |

本地模拟投递：凭据写入 `app.outbox-dir`（默认 `./data/outbox/<username>.txt`）并打印日志，
本地验证时直接读取该文件即可拿到 6 位数字凭据。

## 流程语义

1. **注册/登录**：口令经 BCrypt 哈希存储，同时写入口令历史；登录成功签发 256 位随机会话令牌，
   库中只存 SHA-256 摘要，会话有有效期（默认 24h）且可主动撤销（logout）。
2. **申请凭据**：对存在与不存在的账户返回完全相同的响应；存在的账户会收到新凭据，
   同一账户此前未使用的凭据全部作废（任一时刻最多一个可用凭据）。
3. **校验凭据**：`verify` 只读检查不消耗凭据；凭据已使用、已过期、已作废或格式非法时，
   统一返回 `400 invalid or expired reset credential`，不区分具体原因。
4. **确认重置**：`confirm` 再次校验凭据（悲观锁防并发重放），新口令须满足强度策略
   （8–128 位且含字母与数字）且不得与历史口令相同；成功后凭据标记已用、
   该账户全部会话立即撤销、旧口令立即失效。

## 安全约束

- **不可逆存储**：口令 BCrypt；会话令牌与重置凭据只存 SHA-256 摘要，明文仅出现在投递渠道。
- **防枚举**：`request` 响应与账户是否存在无关；限流对存在/不存在账户一视同仁。
- **单次使用与有效期**：凭据一次性，默认 10 分钟过期；连续校验失败 5 次自动作废，防在线爆破。
- **并发确定性**：申请按账户行悲观锁串行化，并发申请最终恰好一个凭据可用；
  确认按凭据行悲观锁保证只被消费一次。
- **越权防护**：会话令牌与重置凭据均绑定属主账户，跨账户使用一律拒绝；
  受保护端点缺失或伪造令牌返回 401。
- **限流**：同一账户申请窗口默认 10 分钟最多 3 次（`app.reset-request-max/window`）。
- **可审计**：注册、登录成功/失败、登出、申请、限流、校验成功/失败、确认成功/失败、
  会话批量撤销均落 `audit_events` 表；审计在独立事务提交，业务回滚不丢记录。
- **重启恢复**：H2 文件库（`./data/appdb`）持久化账户、会话、凭据、口令历史与审计；
  重启后未使用且未过期的凭据仍可用，已使用的凭据不会恢复为可用。

## 配置项（`application.properties`）

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `app.session-ttl` | `PT24H` | 会话有效期 |
| `app.reset-token-ttl` | `PT10M` | 重置凭据有效期 |
| `app.reset-max-attempts` | `5` | 凭据校验失败上限，达到即作废 |
| `app.reset-request-window` | `PT10M` | 申请限流窗口 |
| `app.reset-request-max` | `3` | 窗口内最大申请次数 |
| `app.outbox-dir` | `./data/outbox` | 本地模拟投递目录 |

## 测试覆盖

- `AccountFlowTest`：注册/登录/登出、弱口令与重复注册、登录失败审计
- `ResetFlowTest`：完整重置流程、凭据重放、格式非法统一拒绝、失败计数作废、口令历史、二次申请作废旧凭据
- `EnumerationTest`：存在/不存在账户响应不可区分
- `ResetExpiryTest`：过期凭据统一拒绝
- `ResetRateLimitTest`：申请限流（含不存在账户）
- `ConcurrentResetRequestTest`：并发申请最终恰好一个凭据可用
- `AuthorizationTest`：缺失/伪造令牌、跨账户使用凭据等越权场景
- `RestartRecoveryTest`：重启后凭据与审计记录的恢复语义
