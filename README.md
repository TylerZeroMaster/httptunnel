# Easy HTTP Tunneling

## What does it do?

The goal is to make it easy to tunnel through http(s).

## Why was it made?

Not a new concept, but I had wanted to see how easy this would be. Parts of the underlying library were copy/pasted from github.com/gorilla/websocket (almost everything in [helpers.go](./helpers.go)). I think there could be other advantages to tunneling established protocols over http as well. 

Take ssh, for example. By tunneling ssh over http you:

- Make it less clear that ssh is available (since it goes through port 80/443 instead of a different port)
- Close one more port on your firewall
- Can use http middlewares to some degree
- Can easily make urls dynamic (maybe like one-time passwords, but instead urls for connections)
- Ensure you are connecting to the correct (https) server with Domain Validation (or better) certificates

## Try it yourself

```sh
$ go get -u github.com/TylerZeroMaster/httptunnel
```

See [httpssh](https://github.com/TylerZeroMaster/httpssh) for a full example.


## Where to next?

This is probably the end. If I did continue, I would probably
- Work on improving the options for the dialer/hijacker. Ideally, more boilerplate code could be kept in these standard implementations and options, or some other mechanism, could be fleshed out for more customization.
- Fix some of the minor issues that exist in the examples (no show stoppers that I am aware of)
- Get to 100% test coverage (currently around 80%)
