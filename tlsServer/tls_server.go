package tls_server

import (
	"net"
	"crypto/tls"
	"net/http"
	//"GoQuicProxy/constValue"
	//"bytes"
	//"io"
	"bufio"
	"GoQuicProxy/genCerts"
)

//建立连接
func Dial(client net.Conn, addr string) (net.Conn, error) {
	//cer, err := tls.LoadX509KeyPair("certs/quicioCert/server.cer", "certs/quicioCert/serverkey.pem") //CA根证书与这个的关系，解决证书问题
	cer, err := genCerts.GenCert(addr)
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

//读取请求
func ReadReq(conn net.Conn) (*http.Request, error) {
	/*var b [constValue.BUFFER_SIZE]byte
	buf := bytes.Buffer{}
	var bs []byte
	var len int
	for {
		n, er := conn.Read(b[:])
		if n > 0 {
			_, ew := buf.Write(b[:n])
			if ew != nil {
				return nil, ew
			}
		}
		if er != nil {
			if er != io.EOF {
				return nil, er
			}
			break
		}
		//连接不中断，因此需要检测读取到末尾就跳出，防止阻塞
		if buf.Len() > 3 {
			bs = buf.Bytes()
			len = buf.Len()
			if bs[len-4] == '\r' && bs[len-3] == '\n' && bs[len-2] == '\r' && bs[len-1] == '\n' {
				break
			}
		}
	}
	br := bufio.NewReader(bytes.NewReader(buf.Bytes()))*/
	return http.ReadRequest(bufio.NewReader(conn))
}

//发回响应
func Write(conn net.Conn, buf []byte) error {
	_, err := conn.Write(buf)
	if err != nil {
		return err
	}
	return nil
}