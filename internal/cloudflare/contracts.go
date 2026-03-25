package cloudflare

const (
	ProtocolCFConnectIP                   = "cf-connect-ip"
	ProtocolConnectStream                 = "connect-stream"
	CloudflareQuirkResponseError          = "response_error"
	CloudflareQuirkUnauthorized           = "unauthorized"
	CloudflareQuirkRateLimited            = "rate_limited"
	CloudflareQuirkRouteUnavailable       = "route_unavailable"
	CloudflareQuirkProtocolMismatch       = "protocol_mismatch"
	CloudflareQuirkMissingDatagrams       = "missing_datagrams"
	CloudflareQuirkMissingExtendedConnect = "missing_extended_connect"
	CloudflareQuirkProtocolError          = "protocol_error"
)

type Quirks struct {
	Name                       string
	UseCFConnectIP             bool
	RequireDatagrams           bool
	MapUnauthorizedToAuthError bool
}

type Snapshot struct {
	Protocol string
	Endpoint string
	Quirks   Quirks
}

func DefaultQuirks() Quirks {
	return Quirks{
		Name:                       "cloudflare-default",
		UseCFConnectIP:             true,
		RequireDatagrams:           true,
		MapUnauthorizedToAuthError: true,
	}
}
