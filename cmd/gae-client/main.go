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
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/xuiv/gae_proxy"
)

var (
	local      = flag.String("local", "127.0.0.1:1080", "Local address to bind to, or - for stdin/out")
	server     = flag.String("server", "http://127.0.0.1:8080/", "gae_proxy server to use.")
	username   = flag.String("username", "user", "Username to use.")
	password   = flag.String("password", "pass", "Password to use.")
	socks_auth = flag.Bool("socksauth", false, "socks5 proxy if use auth")
	socks_user = flag.String("socksuser", "user", "socks5 proxy auth user")
	socks_pass = flag.String("sockspass", "pass", "socks5 proxy auth pass")
)

var (
	no_auth   = []byte{0x05, 0x00}
	with_auth = []byte{0x05, 0x02}

	auth_success = []byte{0x05, 0x00}
	auth_failed  = []byte{0x05, 0x01}

	connect_success = []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

type Socks5ProxyHandler struct{}

type Handler interface {
	Handle(connect net.Conn, server string, username string, password string, connectid string)
}

func (socks5 *Socks5ProxyHandler) Handle(connect net.Conn, server string, username string, password string, connectid string) {
	defer connect.Close()
	if connect == nil {
		return
	}

	b := make([]byte, 1024)

	n, err := connect.Read(b)
	if err != nil {
		return
	}

	if b[0] == 0x05 {

		if *socks_auth == false {
			connect.Write(no_auth)
		} else {
			connect.Write(with_auth)

			n, err = connect.Read(b)
			if err != nil {
				return
			}

			user_length := int(b[1])
			luser := string(b[2:(2 + user_length)])
			pass_length := int(b[2+user_length])
			lpass := string(b[(3 + user_length):(3 + user_length + pass_length)])

			if luser == *socks_user && lpass == *socks_pass {
				connect.Write(auth_success)
			} else {
				connect.Write(auth_failed)
				return
			}
		}

		n, err = connect.Read(b)
		var host string
		switch b[3] {
		case 0x01: //IP V4
			host = net.IPv4(b[4], b[5], b[6], b[7]).String()
		case 0x03: //domain
			host = string(b[5 : n-2]) //b[4] length of domain
		case 0x04: //IP V6
			host = net.IP{b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]}.String()
		default:
			return
		}
		lport := strconv.Itoa(int(b[n-2])<<8 | int(b[n-1]))

		lserver, err := gae_proxy.Connect(server, username, password, string(net.JoinHostPort(host, lport)), connectid)
		if err != nil {
			return
		}
		connect.Write(connect_success)

		go io.Copy(lserver, connect)
		io.Copy(connect, lserver)
	}
}

func main() {
	flag.Parse()

	localListen, err := net.Listen("tcp", *local)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	for {
		localConn, err := localListen.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			continue
		}
		connectid := fmt.Sprint(localConn)
		connectid = connectid[1:]
		fmt.Println("connectid:", connectid)

		var handler Handler = new(Socks5ProxyHandler)
		go handler.Handle(localConn, *server, *username, *password, string(connectid))
	}
}
