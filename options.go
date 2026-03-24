package amz

type Options struct {
	Storage StorageOptions
	Listen  ListenOptions
	HTTP    HTTPOptions
	SOCKS5  SOCKS5Options
	TUN     TUNOptions
}

type StorageOptions struct {
	Path string
}

type ListenOptions struct {
	Address string
}

type HTTPOptions struct {
	Enabled bool
}

type SOCKS5Options struct {
	Enabled bool
}

type TUNOptions struct {
	Enabled bool
}

func (o Options) normalized() Options {
	normalized := o
	if normalized.Listen.Address == "" && (normalized.HTTP.Enabled || normalized.SOCKS5.Enabled) {
		normalized.Listen.Address = "127.0.0.1:9811"
	}
	return normalized
}
