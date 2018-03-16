package tls_server

import (
	"net"
	"crypto/tls"
	"GoQuicProxy/utils"
)

//建立连接
func Dial(client net.Conn, addr string) (net.Conn, error) {
	cer, err := utils.GenCert(addr)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{Certificates: []tls.Certificate{*cer}}
	conn := tls.Server(client, config)
	err = conn.Handshake()
	if err != nil {
		return nil, err
	}
	return conn, nil
}
