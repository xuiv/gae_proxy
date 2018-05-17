// Copyright (c) 2015, Segiusz 'q3k' Bazanski <sergiusz@bazanski.pl>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	//"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/xuiv/gae_proxy"
	"google.golang.org/appengine"
	"google.golang.org/appengine/socket"
)

var (
	//listen   = flag.String("listen", "0.0.0.0:8080", "Address to bind HTTP server to")
	userfile = flag.String("userfile", "gae_proxy.conf", "Path of user config file")
)

var nonceMap = map[string][]byte{}
var gaemux sync.Mutex

func authHandler(w http.ResponseWriter, r *http.Request) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		gae_proxy.WriteHTTPError(w, "Internal error.")
		return
	}

	username := r.URL.Query().Get("username")
	connectid := r.URL.Query().Get("connectid")

	gaemux.Lock()
	_, ok := UserGet(username)
	gaemux.Unlock()
	if !ok {
		gae_proxy.WriteHTTPError(w, "No such user.")
		return
	}

	gaemux.Lock()
	nonceMap[fmt.Sprintf("%s:%s", username, connectid)] = nonce
	gaemux.Unlock()
	gae_proxy.WriteHTTPData(w, nonce)
}

func connectHandler(w http.ResponseWriter, r *http.Request) {
	remote_host := r.URL.Query().Get("remote_host")
	if remote_host == "" {
		gae_proxy.WriteHTTPError(w, "Invalid host")
		return
	}

	remote_port, err := strconv.Atoi(r.URL.Query().Get("remote_port"))
	if err != nil || remote_port > 0xFFFF {
		gae_proxy.WriteHTTPError(w, "Invalid port number.")
		return
	}
	username := r.URL.Query().Get("username")
	connectid := r.URL.Query().Get("connectid")
	if username == "" {
		gae_proxy.WriteHTTPError(w, "Invalid username")
		return
	}
	user, ok := UserGet(username)
	if !ok {
		gae_proxy.WriteHTTPError(w, "Invalid username")
		return
	}
	gaemux.Lock()
	nonce, ok := nonceMap[fmt.Sprintf("%s:%s", username, connectid)]
	gaemux.Unlock()
	if !ok {
		gae_proxy.WriteHTTPError(w, "Invalid username")
		return
	}

	proof_b64 := r.URL.Query().Get("proof")
	decodeLen := base64.StdEncoding.DecodedLen(len(proof_b64))
	proof := make([]byte, decodeLen)
	n, err := base64.StdEncoding.Decode(proof, []byte(proof_b64))
	if err != nil {
		gae_proxy.WriteHTTPError(w, "Invalid nonce")
		return
	}
	proof = proof[:n]

	authenticated := user.Authenticate(nonce, proof)
	if !authenticated {
		gae_proxy.WriteHTTPError(w, "Invalid nonce")
		return
	}

	commandChannel := make(chan workerCommand, 10)
	responseChannel := make(chan workerResponse, 10)
	fmt.Printf("Connecting to %s:%d...\n", remote_host, remote_port)
	ctx := appengine.NewContext(r)
	remote, err := socket.Dial(ctx, "tcp", fmt.Sprintf("%s:%d", remote_host, remote_port))
	//remote, err := net.Dial("tcp", fmt.Sprintf("%s:%d", remote_host, remote_port))
	if err != nil {
		gae_proxy.WriteHTTPError(w, fmt.Sprintf("Could not connect to %s:%d %s", remote_host, remote_port, err.Error()))
		return
	}
	workerUuid := fmt.Sprint(remote)
	workerUuid = workerUuid[1:] + connectid
	fmt.Println("workerUuid:", workerUuid)

	newWorker := worker{remote: remote, commandChannel: commandChannel, responseChannel: responseChannel, uuid: workerUuid}
	gaemux.Lock()
	workerMap[workerUuid] = newWorker
	gaemux.Unlock()

	gae_proxy.WriteHTTPOK(w, workerUuid)

	go socketWorker(newWorker)
}

func syncHandler(w http.ResponseWriter, r *http.Request) {
	workerUuid := r.URL.Query().Get("uuid")
	gaemux.Lock()
	worker, ok := workerMap[workerUuid]
	gaemux.Unlock()
	if ok {
		if r.Method == "POST" {
			r.ParseForm()
			if b64_parts, ok := r.Form["data"]; ok {
				b64 := b64_parts[0]
				decodeLen := base64.StdEncoding.DecodedLen(len(b64))
				data := make([]byte, decodeLen)
				n, err := base64.StdEncoding.Decode(data, []byte(b64))
				if err != nil {
					gae_proxy.WriteHTTPError(w, "Could not decode B64.")
				} else {
					worker.commandChannel <- workerCommand{command: command_data, extra: data[:n]}
					gae_proxy.WriteHTTPOK(w, "Sent.")
				}
			} else {
				gae_proxy.WriteHTTPError(w, "Data is required.")
			}
		} else {
			response := <-worker.responseChannel
			switch response.response {
			case response_data:
				gae_proxy.WriteHTTPData(w, response.extra_byte)
			case response_quit:
				gae_proxy.WriteHTTPQuit(w, response.extra_string)
			}
		}
	} else {
		gae_proxy.WriteHTTPError(w, "No such UUID")
	}
}

func main() {
	flag.Parse()
	loadUsersFromFile(*userfile)
	http.HandleFunc(gae_proxy.EndpointConnect, connectHandler)
	http.HandleFunc(gae_proxy.EndpointSync, syncHandler)
	http.HandleFunc(gae_proxy.EndpointAuth, authHandler)
	appengine.Main()
	//http.ListenAndServe(*listen, nil)
}
