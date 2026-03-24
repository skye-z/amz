// Package amz exposes the SDK-first public API for connecting to Cloudflare
// WARP through the implementation contained in this repository.
//
// The package is intentionally designed around a single client entry point:
//
//	client, err := amz.NewClient(opts)
//	if err != nil {
//	    panic(err)
//	}
//	defer client.Close()
//	if err := client.Start(ctx); err != nil {
//	    panic(err)
//	}
//
// Most implementation details are expected to live under internal/ and are not
// part of the stable public SDK surface.
package amz
