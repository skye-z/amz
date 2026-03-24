package session

import "github.com/skye-z/amz/observe"

// connectionStats 保留 kernel 兼容层入口，真实实现迁移到 observe.ConnectionStats。
type connectionStats = observe.ConnectionStats
