module github.com/TylerZeroMaster/httptunnel/cmd/totp

go 1.23.0

replace github.com/TylerZeroMaster/httptunnel => ../..

require (
	github.com/TylerZeroMaster/httptunnel v0.0.0-00010101000000-000000000000
	github.com/docopt/docopt-go v0.0.0-20180111231733-ee0de3bc6815
)

require github.com/google/uuid v1.6.0

require golang.org/x/net v0.33.0 // indirect
