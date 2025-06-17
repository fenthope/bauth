package bauth

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/infinite-iroha/touka"
)

const (
	authHeader = "Authorization"
	authScheme = "Basic "
)

// ValidatorFunc 是用户提供的核心验证函数
// 它接收从请求中解析出的用户名和密码，并返回一个布尔值，
// 指示这对凭证是否有效
//
// 参数:
//   - c (*touka.Context): 当前请求的上下文，可以用于访问数据库连接等
//   - username (string): 从 Authorization 头部解析出的用户名
//   - password (string): 从 Authorization 头部解析出的密码
//
// 返回:
//   - bool: 如果凭证有效，返回 true；否则返回 false
type ValidatorFunc func(c *touka.Context, username, password string) bool

// AuthOptions 用于配置 BasicAuth 中间件
type AuthOptions struct {
	// Validator 是用于验证用户名和密码的核心函数这是必需的
	Validator ValidatorFunc

	// Realm 是在返回 401 Unauthorized 响应时，在 WWW-Authenticate 头部中使用的域名
	// 默认为 "Authorization Required"
	Realm string

	// OnAuthFailed 是一个可选的回调函数，当认证失败时调用
	// 如果为 nil，将使用默认的处理方式（发送标准的 401 响应）
	OnAuthFailed func(c *touka.Context, realm string)

	// RequireTLS 强制只在 HTTPS (TLS) 连接上进行 Basic Auth
	// 默认为 false，但在生产环境中强烈建议将此设置为 true
	RequireTLS bool
}

// defaultOnAuthFailed 是默认的认证失败处理器
func defaultOnAuthFailed(c *touka.Context, realm string) {
	c.SetHeader("WWW-Authenticate", `Basic realm="`+realm+`"`)
	//http.Error(c.Writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	c.ErrorUseHandle(http.StatusUnauthorized, fmt.Errorf("Unauthorized"))
	if !c.IsAborted() {
		c.Abort()
	}
}

// BasicAuth 返回一个 HTTP Basic Authentication 中间件
// 它解析凭证，并使用用户提供的 ValidatorFunc 来决定是否授权
func BasicAuth(opts AuthOptions) touka.HandlerFunc {
	if opts.Validator == nil {
		panic("bauth: ValidatorFunc cannot be nil") // 使用英文 panic 信息
	}
	if opts.Realm == "" {
		opts.Realm = "Authorization Required"
	}
	if opts.OnAuthFailed == nil {
		opts.OnAuthFailed = defaultOnAuthFailed
	}

	return func(c *touka.Context) {
		if opts.RequireTLS && c.Request.TLS == nil {
			opts.OnAuthFailed(c, opts.Realm)
			return
		}

		auth := c.GetReqHeader(authHeader)
		if auth == "" {
			opts.OnAuthFailed(c, opts.Realm)
			return
		}

		if !strings.HasPrefix(auth, authScheme) {
			opts.OnAuthFailed(c, opts.Realm)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(auth[len(authScheme):])
		if err != nil {
			opts.OnAuthFailed(c, opts.Realm)
			return
		}

		pair := strings.SplitN(string(payload), ":", 2)
		if len(pair) != 2 {
			opts.OnAuthFailed(c, opts.Realm)
			return
		}

		username := pair[0]
		password := pair[1]

		// 调用用户提供的验证函数
		if opts.Validator(c, username, password) {
			// 验证成功
			c.Set("authenticated_user", username)
			c.Next() // 继续处理链
		} else {
			// 验证失败
			opts.OnAuthFailed(c, opts.Realm)
		}
	}
}

// BasicAuthForStatic 是一个便捷函数，它使用一个静态的、只读的用户名密码 map 作为验证源
// 密码比较使用了 crypto/subtle.ConstantTimeCompare 以防止时序攻击
// 这对于简单的应用场景或测试非常有用
//
// 参数:
//   - secrets (map[string]string): 一个从用户名到密码的映射这里的密码应该是明文
//   - realm (string): WWW-Authenticate 头部中使用的域名
func BasicAuthForStatic(secrets map[string]string, realm string) touka.HandlerFunc {
	if len(secrets) == 0 {
		panic("bauth: secrets map cannot be empty for BasicAuthForStatic") // 英文 panic
	}

	opts := AuthOptions{
		Realm: realm,
		Validator: func(c *touka.Context, username, password string) bool {
			// 从 map 中查找预期的密码
			expectedPassword, ok := secrets[username]
			if !ok {
				// 用户不存在
				return false
			}

			// 使用恒定时间比较来防止时序攻击
			// subtle.ConstantTimeCompare 要求两个切片长度相同
			if len(password) != len(expectedPassword) {
				return false
			}
			// 比较密码
			return subtle.ConstantTimeCompare([]byte(password), []byte(expectedPassword)) == 1
		},
		RequireTLS: false,
	}

	return BasicAuth(opts)
}
