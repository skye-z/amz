package session

import "github.com/skye-z/amz/internal/config"

// connectionStats 保留 kernel 兼容层入口，真实实现迁移到 config.ConnectionStats。
type connectionStats = config.ConnectionStats
