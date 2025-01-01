package httptunnel

import _ "embed"

const Version = "0.1.0"

//go:embed LICENSE
var license string
var License = `
=====================================
github.com/TylerZeroMaster/httptunnel
=====================================

` + license + `
============================
github.com/gorilla/websocket
============================
` + gorillaWebsocketsLicense
