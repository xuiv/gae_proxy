gae_proxy (fork from [crowbar](https://github.com/q3k/crowbar))
=======
```
The Socket API will be enabled for this application once billing has been enabled in the admin console.
```

Intro
-----

gae_proxy is an **EXPERIMENTAL** tool that allows you to establish a secure circuit with your existing encrypting TCP endpoints (an OpenVPN setup, an SSH server for forwarding...) when your network connection is limited by a Web proxy that only allows basic port 80 HTTP connectivity.

gae_proxy will tunnel TCP connections over an HTTP session using only GET and POST requests. This is in contrast to most tunneling systems that reuse the CONNECT verb. It also provides basic authentication to make sure nobody who stumbles upon the server steals your proxy to order drugs from Silkroad.

Features
--------

 - Establishes TCP connections via a proxy server using only HTTP GET and POST requests
 - Authenticates users from an authentication file
 - Will probably get you fired if you use this in an office setting

Security & Confidentiality
--------------------------

Crowbar **DOES NOT PROVIDE ANY DATA CONFIDENTIALITY**. While the user authentication mechanism protects from replay attacks to establish connectivity, it will not prevent someone from MITMing the later connection transfer itself, or from MITMing whole sessions. So, yeah, make sure to **use it only tunnel an SSH or OpenVPN server**, and **firewall off most outgoing connections on your proxy server** (ie. only allow access to an already publicly-available SSH server)

The authentication code and crypto have not been reviewed by cryptographers. I am not a cryptographer. You should consider this when deploying Crowbar.

Known bugs
----------

The crypto can be improved vastly to enable server authentication and make MITMing more difficult. It could also use a better authentication setup to allow the server to keep password hashes instead of plaintext.

The server should include some filtering functionality for allowed remote connections.

The server lacks any cleanup functions and rate limiting, so it will leak both descriptors and memory - this should be fixed soon.

Is it any good?
---------------

Eh, it works. I'm not an experienced Golang programmer though, so the codebase is probably butt-ugly.

License
-------

BSD 2-clause, 'nuff said.

Usage
=====

Server setup
------------

deploy on gae, login in https://console.cloud.google.com, open Cloud Shell:

    go get google.golang.org/appengine
    go get github.com/xuiv/gae_proxy/...
    mv $GOPATH/src/github.com/xuiv/gae_proxy/vendor/github.com/pborman $GOPATH/src/github.com/
    cd $GOPATH/src/github.com/xuiv/gae_proxy/cmd/gae-proxy/
    gcloud app deploy app.yaml


Client setup
------------

This assumes you're running Linux on your personal computer. If not, you're on your own.

default gae-client will listen in port:1080

    gae-client -server http://xxxx.appspot.com:80