# BAuth

Touka框架的Basic Auth中间件, 提供Basic Auth规范性框架, 将凭据验证的具体逻辑交由用户

### 概述

本中间件负责解析 HTTP 请求中的 `Authorization: Basic` 头部，并将提取出的用户名和密码传递给用户定义的验证逻辑。如果认证成功，请求继续处理；否则，返回 401 Unauthorized 响应。

### 安装

将 `bauth` 包添加到你的 Go 项目中：

```bash
go get github.com/fenthope/bauth
```

### 使用方法

`bauth` 提供了两种主要的使用方式：`BasicAuth` (自定义验证) 和 `BasicAuthForStatic` (静态凭据验证)。

#### 1. `bauth.BasicAuth`: 自定义验证逻辑 (推荐)

这种方式适用于需要从数据库、配置文件或其他服务动态验证用户凭据的场景。

**核心：** 你需要提供一个 `bauth.ValidatorFunc`。

**`ValidatorFunc` 签名：**

```go
type ValidatorFunc func(c *touka.Context, username, password string) bool
```

*   `c`: 当前请求上下文，可用于访问依赖（如数据库连接）。
*   `username`, `password`: 从请求头解析出的凭据。
*   **返回值**: `true` 表示凭据有效，`false` 表示无效。

**代码示例：**

```go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/fenthope/bauth"    
	"github.com/infinite-iroha/touka" 
	"golang.org/x/crypto/bcrypt"   
)

// 模拟用户数据库 (生产环境应从实际数据库加载)
// 键是用户名，值是 bcrypt 哈希后的密码
var usersDB = make(map[string]string) 

func init() {
	// 在程序启动时，模拟加载用户数据。实际中应从数据库加载。
	// 请注意，每次 bcrypt.GenerateFromPassword 都会因随机盐而产生不同的哈希。
	hashedAdminPass, _ := bcrypt.GenerateFromPassword([]byte("admin_secure_pass"), bcrypt.DefaultCost)
	usersDB["admin"] = string(hashedAdminPass)
}

func main() {
	router := touka.Default()

	// 1. 定义你的验证函数
	// customValidator 从模拟数据库中验证用户名和密码
	customValidator := func(c *touka.Context, username, password string) bool {
		hashedPasswordFromDB, userExists := usersDB[username]
		if !userExists {
			return false // 用户不存在
		}
		// 使用 bcrypt 比较用户提供的密码和存储的哈希密码
		return bcrypt.CompareHashAndPassword([]byte(hashedPasswordFromDB), []byte(password)) == nil
	}

	// 2. 配置 BasicAuth 中间件选项
	authOptions := bauth.AuthOptions{
		Validator:  customValidator, // 必需：指定你的验证函数
		Realm:      "Protected API", // 可选：设置认证领域
		RequireTLS: true,            // 生产环境强烈建议设置为 true
		// OnAuthFailed: func(c *touka.Context, realm string) {
		//     // 可选：自定义认证失败时的响应，例如返回 JSON 错误
		//     c.JSON(http.StatusUnauthorized, touka.H{"status": "error", "message": "Auth failed."})
		//     c.Abort()
		// },
	}

	// 3. 将中间件应用到路由组或单个路由
	apiGroup := router.Group("/api")
	{
		apiGroup.Use(bauth.BasicAuth(authOptions)) // 应用 BasicAuth 中间件

		apiGroup.GET("/data", func(c *touka.Context) {
			// 如果请求到达这里，说明认证已成功
			// 中间件会将认证成功的用户名存储在 Context 中，键为 "authenticated_user"
			username, _ := c.Get("authenticated_user").(string) 
			c.JSON(http.StatusOK, touka.H{"message": fmt.Sprintf("Welcome, %s!", username)})
		})
	}

	log.Println("Server listening on :8080")
	router.Run(":8080")
}
```

#### 2. `bauth.BasicAuthForStatic`: 静态凭据验证 (仅限测试/开发)

**代码示例：**

```go
func main() {
	router := touka.Default()

	// 测试用演示
	staticUsers := map[string]string{
		"test":     "123456",
		"monitor":  "view_pass",
	}

	// 2. 将中间件应用到路由组或单个路由
	staticProtectedGroup := router.Group("/static-protected")
	{
		// 认证领域为 "Static Debug Access"
		staticProtectedGroup.Use(bauth.BasicAuthForStatic(staticUsers, "Static Debug Access"))

		staticProtectedGroup.GET("/metrics", func(c *touka.Context) {
			username, _ := c.Get("authenticated_user").(string)
			c.JSON(http.StatusOK, touka.H{"message": fmt.Sprintf("Metrics for %s.", username)})
		})
	}

	log.Println("Server listening on :8080")
	router.Run(":8080")
}
```

### `AuthOptions` 配置选项

`bauth.AuthOptions` 结构体的所有可用字段及其说明：

| 字段名         | 类型                                      | 作用                                                                                                                                                                                                                                           | 默认值/备注                                                              |
| :------------- | :---------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------- |
| `Validator`    | `bauth.ValidatorFunc`                     | **必需。** 用于验证用户名和密码的核心函数。你在此处实现自定义的凭据校验逻辑。                                                                                                                                                              | 无 (必须提供)                                                            |
| `Realm`        | `string`                                  | 在返回 `401 Unauthorized` 响应时，在 `WWW-Authenticate` 头部中使用的域名或提示信息。                                                                                                                                                         | `"Authorization Required"`                                               |
| `OnAuthFailed` | `func(c *touka.Context, realm string)` | 可选的回调函数。当认证失败时（例如无凭据、凭据格式错误、`Validator` 返回 `false`、或 `RequireTLS` 检查失败），此函数将被调用。可用于自定义错误响应。                                                                                              | 默认处理：发送标准 `401 Unauthorized` 和 `WWW-Authenticate` 头部。         |
| `RequireTLS`   | `bool`                                    | 如果设置为 `true`，中间件将强制只允许通过 HTTPS (TLS) 连接的请求进行 Basic Auth。对于非 HTTPS 的请求，将直接调用 `OnAuthFailed`。**强烈建议在生产环境中将此设置为 `true`**。                                                                       | `false`                                                                  |

### 认证成功后的用户信息

如果认证成功，中间件会将认证的用户名存储在 `touka.Context` 中，键为 `"authenticated_user"`。你可以在后续的 Handler 中通过 `c.Get("authenticated_user").(string)` 来获取它。

```go
apiGroup.GET("/data", func(c *touka.Context) {
    username, exists := c.Get("authenticated_user").(string)
    if !exists {
        // 通常不会发生，除非 Context 被意外修改
        c.JSON(http.StatusInternalServerError, touka.H{"message": "User context not found."})
        return
    }
    c.JSON(http.StatusOK, touka.H{"message": fmt.Sprintf("Welcome, %s!", username)})
})
```