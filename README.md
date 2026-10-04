# account-password-reset-java

本地可端到端运行的账户口令重置与恢复服务（Spring Boot 3 / Java 17 / H2 文件库），
不依赖任何外部服务。重置凭据的交付渠道由本地模拟（日志 + 内存 outbox）。

## 运行与测试

```bash
mvn spring-boot:run   # 启动服务，默认端口 8080，数据落盘 ./data/
mvn test              # 运行全部自动化测试
```

## 流程概览

1. **注册** `POST /api/accounts/register`：口令经 PBKDF2-HmacSHA256（21 万次迭代、
   随机盐）散列后存储，同时写入口令历史，无法还原。
2. **登录** `POST /api/auth/login`：校验口令后签发会话。会话令牌为 256 位随机值，
   服务端只存 SHA-256 散列；账户不存在与口令错误返回完全相同的
   `401 invalid_credentials`，且对不存在账户执行等时哑比较。
3. **申请重置** `POST /api/password-reset/request`：无论账户是否存在，一律返回
   `202` 且响应体为空。存在账户时生成一次性凭据（`rst_` + 256 位随机值），
   只存 SHA-256 散列，原文经本地模拟渠道 `LocalResetDelivery` 投递
   （写入日志与内存 outbox，测试可读取）。
4. **校验凭据** `POST /api/password-reset/verify`：凭据可用返回 `204`；
   已使用 / 已过期 / 被取代 / 格式非法 / 不存在，统一返回
   `401 {"error":"invalid_credential"}`，不泄露内部状态。
5. **确认重置** `POST /api/password-reset/confirm`：校验通过后在同一事务内
   设置新口令、将凭据标记为已用、撤销该账户全部会话。新口令必须满足强度策略
   且不得与任一历史口令相同；策略失败时凭据保持可用，可换口令重试。

## 安全语义与约束

- **不可还原存储**：口令 PBKDF2 散列；会话令牌与重置凭据只存 SHA-256 散列。
- **一次性 + 有效期**：凭据默认 15 分钟有效，成功使用即作废；同一账户再次申请
  会取代（supersede）此前所有未用凭据，任意时刻最多一个凭据可用。
- **并发确定性**：申请时对账户行加悲观写锁（`SELECT ... FOR UPDATE`），
  并发申请被串行化，最终恰好一个凭据可用，行为可复现。
- **频率限制**：同一账户 10 分钟内最多 3 次申请（可配置）。超限后接口仍返回
  `202`，但不再签发凭据，仅记录审计事件。
- **枚举防护**：申请、登录接口对存在/不存在账户返回不可区分的响应；
  不存在账户的申请不投递、不报错，只留审计记录。
- **口令策略**：长度 10–128，须含大小写字母、数字与特殊字符，不得包含用户名；
  不得与历史口令重复（`400 password_reused`）。
- **重置即失效**：重置成功后旧口令立即失效，该账户全部既有会话被撤销。
- **越权拒绝**：会话相关操作必须持有效 `Bearer` 令牌；撤销他人会话返回
  `403 forbidden` 并记录 `ACCESS_DENIED` 审计事件。
- **审计追溯**：注册、登录、会话签发/撤销、凭据申请/限流/签发/校验/确认、
  越权访问等关键事件全部落库（独立事务提交，业务回滚不丢审计）。
- **重启恢复**：H2 文件库持久化。未使用且未过期的凭据重启后仍可用；
  已使用/已撤销的状态不会恢复；审计记录不丢失。

## 配置项（`app.security.*`）

| 配置 | 默认 | 说明 |
| --- | --- | --- |
| `session-ttl` | `12h` | 会话有效期 |
| `reset-token-ttl` | `15m` | 重置凭据有效期 |
| `reset-rate-limit-max` | `3` | 窗口内每账户最大申请次数 |
| `reset-rate-limit-window` | `10m` | 限流窗口 |

数据库位置由 `spring.datasource.url` 控制，默认 `jdbc:h2:file:./data/account-password-reset`。

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/accounts/register` | 注册（`username`/`password`） |
| `POST` | `/api/auth/login` | 登录，返回 `sessionToken` |
| `POST` | `/api/auth/logout` | 注销当前会话（需 `Bearer`） |
| `GET` | `/api/auth/session` | 查询当前会话（需 `Bearer`） |
| `DELETE` | `/api/sessions/{sessionId}` | 撤销本人指定会话（需 `Bearer`） |
| `POST` | `/api/password-reset/request` | 申请重置凭据（恒 `202`） |
| `POST` | `/api/password-reset/verify` | 校验凭据（不消费） |
| `POST` | `/api/password-reset/confirm` | 消费凭据并设置新口令 |

## 测试覆盖

- `AuthFlowTests`：注册/登录/注销、弱口令、重复用户名、登录失败不可区分、
  会话令牌散列存储、按 id 撤销会话与越权拒绝、审计事件。
- `PasswordResetTests`：枚举探测不可区分、完整重置流程、凭据重放、过期、
  格式非法与统一拒绝、申请取代、口令历史、弱口令后可重试、限流、会话全量撤销。
- `PasswordResetConcurrencyTests`：并发申请最终恰好一个凭据可用，多轮突发可复现。
- `RestartRecoveryTests`：文件库 + 上下文重启，验证未用凭据可用、已用凭据不复活、
  会话撤销状态与审计记录持久。
