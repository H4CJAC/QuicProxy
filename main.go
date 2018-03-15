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
	"GoQuicProxy/genCerts"
	"GoQuicProxy/tlsServer"
	"github.com/lucas-clemente/quic-go/h2quic"
)



//入口
func main() {
	log.SetFlags(log.LstdFlags|log.Lshortfile)
	//加载根证书
	err := genCerts.LoadRootCA()
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
		qPort, err := isQuicSupported("https://" + address)
		if err != nil {
			log.Println(err)
			//return
		}
		//log.Printf("IsQuicSupported: %s %v\n", address, qPort != "")
		if qPort != "" {
			tranRepost(client, address, qPort)
		}else {
			simpleRepost(client, address, method, req)
		}
	}else {
		simpleRepost(client, address, method, req)
	}

}

//是否支持quic
func isQuicSupported(address string) (string, error) { //如何更快检测？？？？
	if strings.Contains(address, "www.google.com") || strings.Contains(address, "www.youtube.com") || strings.Contains(address, "ytimg") {
		return ":443", nil
	}
	res, err := http.DefaultClient.Head(address)
	if err != nil {
		return "", err
	}
	altsvc := res.Header.Get("Alt-Svc")
	if altsvc == "" {
		return "", nil
	}
	//如何处理得更到位？？？？要截取到quic=443？？？还是综合什么考虑？？？暂时还有越界问题
	quicPort := altsvc[strings.IndexByte(altsvc, ':'):strings.IndexByte(altsvc, ';')-1]
	//log.Printf("%s\n%#v\n", address, res)
	res.Body.Close()
	return quicPort, nil
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
		/*if err == io.EOF && waits < constValue.WAIT_COUNT {
			waits ++
			log.Printf("Waiting: %s %d\n", conn.RemoteAddr().String(), waits)
			time.Sleep(constValue.WAIT_TIME)
			continue
		}*/
		log.Println(err, req == nil, address)
		return
	}
	if req == nil {
		return
	}
	//log.Printf("QuicRequest: %s\n", req.URL)
	//发送quic请求并接收响应
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
	//cli := quic_client.Quic_cli
	cli.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return constValue.REDIRECT_ERR
	}
	res, err := cli.Do(req)
	if err != nil {
		log.Println(err)
		if !strings.Contains(err.Error(), constValue.REDIRECT_ERR.Error()) { //非跳转
			cli = &http.Client{}
			cli.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return constValue.REDIRECT_ERR
			}
			res, err = cli.Do(req)
			if err != nil {
				log.Println(err)
				if !strings.Contains(err.Error(), constValue.REDIRECT_ERR.Error()) {
					return
				}
			}
			//return
		}else {
			res.ContentLength = 0
		}
	}

	//log.Printf("QuicResponse: %s\n", res.StatusCode)
	////接收响应
	/*var b [constValue.BUFFER_SIZE]byte
	buf := &bytes.Buffer{}
	for {
		n, err := res.Body.Read(b[:])
		if n > 0 {
			buf.Write(b[:n])
		}
		if err != nil {
			if err != io.EOF {
				log.Println(err)
				return
			}
			break
		}
	}
	*/
	//发回tls响应
	/*tls_res := http.Response{
		Status: res.Status,
		StatusCode: res.StatusCode,
		ProtoMajor: res.ProtoMajor,
		ProtoMinor: res.ProtoMinor,
		Header: res.Header,
		//ContentLength: res.ContentLength,
		TransferEncoding: res.TransferEncoding,
		Trailer: res.Trailer,
		Request: res.Request,
		Close: res.Close,
		Uncompressed: res.Uncompressed,
		Proto: res.Proto,
		Body: struct {
			io.Reader
			io.Closer
		}{
			buf,
			res.Body,
		},
	}*/
	//log.Printf("%s\n%#v\n", req.URL, req)
	//log.Printf("%#v\n", res)
	err = res.Write(conn)
	if err != nil {
		log.Println(err, req.URL)
		return
	}
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