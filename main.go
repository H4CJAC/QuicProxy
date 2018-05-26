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
	"GoQuicProxy/utils"
	"GoQuicProxy/quicAddrs"
	"github.com/lucas-clemente/quic-go/h2quic"
	"golang.org/x/net/http2"
	"time"
	"sync"
	"bytes"
)

var (
	roundtrip *h2quic.RoundTripper
	rt_mtx = &sync.RWMutex{}
	h2server = &http2.Server{}
	overflow_bs = [32 * 1024]byte{}
)

/*
程序入口
@param
@return
*/
func main() {

	log.SetFlags(log.LstdFlags|log.Lshortfile)
	//加载根证书
	err := utils.LoadRootCA()
	if err != nil {
		log.Panic(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(constValue.PROXY_PORT))
	if err != nil {
		log.Panic(err)
	}
	constValue.H2_cli.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return constValue.REDIRECT_ERR
	}
	roundtrip = &h2quic.RoundTripper{}
	defer roundtrip.Close()

	log.Println("......started......")

	for {
		client, err := l.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		go handleClientRequest(client)
	}
}

/*
处理client请求
@param client 连接句柄
@return
*/
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

	//解析出url，获得method和address
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

type http2Handler struct {
	qPort string
	address string
}

/*
HTTP/2+TLS服务器调用HTTP/2+QUIC客户端进行请求处理过程
@param resw 响应输出
@param req 请求
@return
 */
func (h *http2Handler) ServeHTTP(resw http.ResponseWriter, req *http.Request) {
	req.Host = req.Host + h.qPort
	req.URL.Host = req.Host
	req.URL.Scheme = "https"
	req.RequestURI = ""
	if req.Body != nil {
		defer req.Body.Close()
	}

	var resp *http.Response
	var err error
	isBroken, hasBrokenCount := quicAddrs.IsBroken("https://" + h.address)
	if !isBroken {
		if req.ContentLength == 0 {

			req.Body = nil

			comp_chan := make(chan bool)
			go func() {
				rt_mtx.RLock()
				resp, err = roundtrip.RoundTrip(req)
				defer close(comp_chan)
				comp_chan <- true
			}()
			select {
			case <- comp_chan:
				rt_mtx.RUnlock()
			case <- time.After(constValue.QUIC_DO_TIMEOUT):
				rt_mtx.RUnlock()
				err = constValue.TIMEOUT_ERR
			}
		}else {
			func() {
				rt_mtx.RLock()
				defer rt_mtx.RUnlock()
				resp, err = roundtrip.RoundTrip(req)
			}()
		}
	}else {
		err = constValue.BROKEN_ERR
	}
	if err != nil {
		log.Println(err, req.URL.String())
		if strings.Contains(err.Error(), "HandshakeTimeout") {
			quicAddrs.IncBroken("https://" + h.address)
		}
		if err != constValue.BROKEN_ERR {
			func () {
				rt_mtx.Lock()
				defer rt_mtx.Unlock()
				go func() {
					err = roundtrip.Close()
					if err != nil {
						log.Println(err)
					}
				}()
				roundtrip = &h2quic.RoundTripper{}
			}()
		}
		resp, err = constValue.H2_cli.Do(req)
		if err != nil {
			log.Println(err)
			if !constValue.IsRedirectErr(err.Error()) {
				log.Println(err)
				resw.WriteHeader(404)
				return
			}
		}
	}else if hasBrokenCount {
		quicAddrs.ResetBroken("https://" + h.address)
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			resw.Header().Add(k, v)
		}
	}
	resw.WriteHeader(resp.StatusCode)
	if resp.ContentLength != 0 {
		n, err := myIOCopy(resw, resp.Body)
		if err != nil {
			log.Println(err, n, req.URL)
			dealOverflow(resp.Body, overflow_bs[:])
		}
	}
}

/*
IO转发
@param dst IO转发目标
@param src IO转发源头
@return (转发数据字节数, 错误)
*/
func myIOCopy(dst io.Writer, src io.Reader) (written int64, err error) {
	buff := &bytes.Buffer{}
	for {
		nr, er := io.CopyN(buff, src, 64 * 1024)
		if nr > 0 {
			nw, ew := dst.Write(buff.Bytes()[:nr])
			buff.Reset()
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != int64(nw) {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	buff = nil
	return written, err
}

/*
处理多余的数据
@param src IO读出流
@param buf 缓冲字节数组
@return
*/
func dealOverflow(src io.Reader, buf []byte) {
	for {
		_, er := src.Read(buf)
		if er != nil {
			if er != io.EOF {
				log.Println(er)
			}
			break
		}
	}
}

/*
协议转换转发
@param client 连接句柄
@param address 目的网站地址
@param qPort 目的网站端口号
@return
*/
func tranRepost(client net.Conn, address string, qPort string) {
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
	h2server.ServeConn(conn, &http2.ServeConnOpts{Handler: &http2Handler{qPort: qPort, address: address}})
}

/*
单纯转发
@param client 连接句柄
@param address 目的网站地址
@param method 请求方式
@param req 请求对象
@return
*/
func simpleRepost(client net.Conn, address string, method string, req *http.Request) {
	server, err := net.Dial("tcp", address)
	if err != nil {
		log.Println(err)
		return
	}
	defer server.Close()
	if method == "CONNECT" {
		fmt.Fprint(client, "HTTP/1.1 200 Connection established\r\n\r\n")
	} else {
		req.Write(server)
	}
	//进行转发
	ExitChan := make(chan bool,1)
	defer close(ExitChan)
	//client转至server
	go func(){
		io.Copy(server, client)
		ExitChan <- true
	}()
	//server转至client
	go func() {
		io.Copy(client, server)
		ExitChan <- true
	}()
	<- ExitChan
	<- ExitChan
}