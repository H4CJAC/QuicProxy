package tls_server

import (
	"net"
	"crypto/tls"
	"GoQuicProxy/utils"
)

/*
建立TLS连接
@param client 连接句柄
@param addr 目的网站地址
@return (TLS连接句柄, 错误)
*/
func Dial(client net.Conn, addr string) (net.Conn, error) {
	cer, err := utils.GenCert(addr)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{Certificates: []tls.Certificate{*cer}, NextProtos: []string{"h2"}}
	conn := tls.Server(client, config)
	err = conn.Handshake()
	if err != nil {
		return nil, err
	}
	return conn, nil
}
