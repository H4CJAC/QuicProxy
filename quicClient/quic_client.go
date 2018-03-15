package quic_client

import (
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/h2quic"
	"net/http"
	"crypto/tls"
)

var (
	rt = &h2quic.RoundTripper{}
	Quic_cli = &http.Client{Transport: rt}
)

//建立连接
func Dial(addr string) (*quic.Stream, error) {
	session, err := quic.DialAddr(addr, &tls.Config{InsecureSkipVerify: true}, nil)
	if err != nil {
		return nil, err
	}
	stream, err := session.OpenStreamSync()
	return &stream, err
}

func Head(addr string) error {
	_, err := Quic_cli.Head("https://"+addr)
	return err
}

//发送请求
func Write(stream quic.Stream, buf []byte) error {
	_, err := stream.Write(buf) //quic.Stream已经将握手处理好了，这里只需要发送http内容就可以了
	if err != nil {
		return err
	}
	return nil
}

//读取响应
func Read(stream quic.Stream, buf []byte) (int, error) {
	n, err := stream.Read(buf)
	if err != nil {
		return n, err
	}
	return n, nil
}
