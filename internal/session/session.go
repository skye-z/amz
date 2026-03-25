package session

// ????? package-level ?????????????????

func NewBootstrapDialer(connection *ConnectionManager, session *ConnectIPSessionManager, delegate HTTPStreamDialer) (*CoreTunnelDialer, error) {
	return NewCoreTunnelDialer(connection, session, delegate)
}
