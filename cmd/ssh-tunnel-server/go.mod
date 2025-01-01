module github.com/TylerZeroMaster/httptunnel/cmd/ssh-tunnel-server

go 1.23.0

replace github.com/TylerZeroMaster/httptunnel => ../..

require (
	github.com/TylerZeroMaster/httptunnel v0.0.0-00010101000000-000000000000
	github.com/docopt/docopt-go v0.0.0-20180111231733-ee0de3bc6815
	github.com/rs/zerolog v1.33.0
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)
