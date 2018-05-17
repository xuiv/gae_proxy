gae_proxy (fork from [crowbar](https://github.com/q3k/crowbar))
=======
```
Google Appengine: 
The Socket API will be enabled for this application once billing has been enabled in the admin console.
```

License
-------

BSD 2-clause, 'nuff said.

Usage
=====

Server setup
------------

deploy on gae, login in https://console.cloud.google.com, open Cloud Shell:

    go get github.com/xuiv/gae_proxy/...
    cd $GOPATH/src/github.com/xuiv/gae_proxy/cmd/gae-proxy/
    gcloud app deploy app.yaml


Client setup
------------

This assumes you're running Linux on your personal computer. If not, you're on your own.

default gae-client will listen in port:1080

    gae-client -server http://xxxx.appspot.com:80
