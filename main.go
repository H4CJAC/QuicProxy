package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"strconv"
	"GoQuicProxy/constValue"
	"net/http"
	"bufio"
	"io"
	"GoQuicProxy/tlsServer"
	"github.com/lucas-clemente/quic-go/h2quic"
	"GoQuicProxy/utils"
	"GoQuicProxy/quicAddrs"
)



//入口
func main() {
	log.SetFlags(log.LstdFlags|log.Lshortfile)
	//加载根证书
	err := utils.LoadRootCA()
	if err != nil {
		log.Panic(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(constValue.PROXY_PORT))
	log.Println("......started......")
	if err != nil {
		log.Panic(err)
	}

	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		go handleClientRequest(client)
	}
}

//处理client请求
func handleClientRequest(client net.Conn) {
	if client == nil {
		return
	}

	//最后需要关闭client
	defer client.Close()

	//读取client请求
	req, err := http.ReadRequest(bufio.NewReader(client))
	if err != nil {
		log.Println(err, req == nil)
		return
	}
	if req == nil {
		return
	}

	////解析出url，获得method、host和address
	method := req.Method
	address := req.Host
	if strings.Index(address, ":") == -1 { //address不带端口， 默认80
		address += ":80"
	}

	//判断是否是https并支持quic
	if method == "CONNECT" {
		isSupport, qPort := quicAddrs.IsQuicSupported("https://" + address)
		if isSupport {
			tranRepost(client, address, qPort)
		}else {
			simpleRepost(client, address, method, req)
		}
	}else {
		simpleRepost(client, address, method, req)
	}

}

//协议转换转发
func tranRepost(client net.Conn, address string, qPort string)  {
	//建立tls连接
	_, err := fmt.Fprint(client, "HTTP/1.1 200 Connection established\r\n\r\n")
	if err != nil {
		log.Println(err, address)
		return
	}
	conn, err := tls_server.Dial(client, address[:strings.IndexByte(address, ':')])
	if err != nil {
		log.Println(err, address)
		return
	}

	defer conn.Close()

	br := bufio.NewReader(conn)
	//读取tls请求
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Println(err, req == nil, address)
		return
	}
	if req == nil {
		return
	}
	//发送quic请求并转发响应
	////发送请求
	req.Host = req.Host + qPort
	req.URL.Host = req.Host
	req.URL.Scheme = "https"
	req.RequestURI = ""
	if req.Body == http.NoBody {
		req.Body = nil
	}
	rt := &h2quic.RoundTripper{}
	cli := &http.Client{Transport: rt}
	cli.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return constValue.REDIRECT_ERR
	}
	res, err := cli.Do(req)
	if err != nil {
		log.Println(err)
		if !isRedirectErr(err.Error()) { //非跳转
			cli = &http.Client{}
			cli.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return constValue.REDIRECT_ERR
			}
			res, err = cli.Do(req)
			if err != nil {
				log.Println(err)
				if !isRedirectErr(err.Error()) {
					return
				}
			}
		}else {
			res.ContentLength = 0
		}
	}
	////转发响应
	err = res.Write(conn)
	if err != nil {
		log.Println(err, req.URL)
		return
	}
}

func isRedirectErr(err string) bool {
	erridx := strings.LastIndexByte(err, ':') + 2
	return erridx >= 2 && erridx < len(err) && err[erridx:] == constValue.REDIRECT_ERR.Error()
}

//单纯转发
func simpleRepost(client net.Conn, address string, method string, req *http.Request) {
	server, err := net.Dial("tcp", address)
	if err != nil {
		log.Println(err)
		return
	}
	if method == "CONNECT" {
		fmt.Fprint(client, "HTTP/1.1 200 Connection established\r\n\r\n")
	} else {
		req.Write(server)
	}
	//进行转发
	ExitChan := make(chan bool,1)
	////client转至server
	go func(){
		io.Copy(server, client)
		ExitChan <- true
	}()
	////server转至client
	go func() {
		io.Copy(client, server)
		ExitChan <- true
	}()
	<- ExitChan
	server.Close()
}