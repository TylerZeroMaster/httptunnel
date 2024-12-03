# Easy HTTP Tunneling

## What does it do?

The goal is to make it easier to tunnel through http.

## Is it ready for production?

Probably not, but maybe. I made it in one hour and only polished it up slightly after that. Granted, most of the underlying library is copy/pasted from github.com/gorilla/websocket (almost everything in [helpers.go](./helpers.go)), so those parts are probably pretty solid.

## Why was it made?

I had the idea during lunch one day. I think there could be other advantages to tunneling established protocols over http as well. 

Take ssh, for example. By tunneling ssh over http you:

- Make it less clear that ssh is available (since it goes through port 80/443 instead of a different port)
- Close one more port on your firewall
- Can use http middlewares to some degree
- Can easily make urls dynamic (maybe like one-time passwords, but instead urls for connections)
- Ensure you are connecting to the correct (https) server with Domain Validation (or better) certificates

## How can I try it?

You can try the ssh tunneling example included on linux/unix systems using openssh.

```sh
# host-running-http-server
$ ssh-tunnel-server
```

Then on your client, configure your ssh connection by adding this to your ~/.ssh/config
```
Host <host-running-ssh-server>
    ProxyCommand ssh-dialer http://<host-running-http-server>:<port>/ssh %h %p
```

Note: https should work too, I just didn't bother to configure that in the example server.

Next, just ssh like normal:

```sh
$ ssh me@host-running-ssh-server
```

### Bonus points: Port 80 with least privilege (optional)

On your server, update your nftables as such:

```sh
sudo nft 'add table inet nat'
# This little packet originated from localhost (you only need this one if you are running your server on the same host as the client)
sudo nft '
add chain inet nat OUTPUT { type nat hook output priority -100; policy accept; }
add rule inet nat OUTPUT oifname "lo" tcp dport 80 counter redirect to :8080
'
# This little packet originated from outside (you only need this one if you are running your server on a different host than the client)
sudo nft '
add chain inet nat PREROUTING { type nat hook prerouting priority -100; policy accept; }
add rule inet nat PREROUTING iifname != "lo" tcp dport 80 counter redirect to :8080
'
```

then you no longer need root to accept connections from port 80. Update your ssh config to remove the port.

## Where to next?

This is probably the end, but if I did continue, I would probably work on improving the options for the dialer/hijacker. Ideally, more boilerplate code could be kept in these standard implementations and options, or some other mechanism, could be fleshed out for more customization. The examples could probably be optimized too since I did not give it too much thought.
