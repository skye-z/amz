package amz

type Status struct {
	Running       bool
	ListenAddress string
	Endpoint      string

	HTTPEnabled   bool
	SOCKS5Enabled bool
	TUNEnabled    bool

	Registered bool
}
