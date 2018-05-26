package constValue

import (
	"errors"
	"time"
	"net/http"
	"golang.org/x/net/http2"
	"strings"
)

const (
	PROXY_PORT = 8081 //代理器端口
	CERTOUTS_PATH = "./certs/outs/" //证书生成路径
	CERT_NODEID = 0 //唯一序列号中的nodeID
	EXPIRE_TIME = 24 * 3600 //QUIC支持性信息缓存有效期，单位秒
	QUIC_DO_TIMEOUT = 30 * time.Second //QUIC连接处理超时时间
	BROKEN_STEP = 20 * time.Second //连接故障处理初始故障时间
)

var (
	REDIRECT_ERR = errors.New("REDI_ERR") //跳转响应提示
	TIMEOUT_ERR = errors.New("TIMEOUT_ERR")
	BROKEN_ERR = errors.New("BROKEN_ERR")
	H2_cli = &http.Client{Transport: &http2.Transport{AllowHTTP: true}}
)

/*
检测是否是跳转响应
@param err 错误信息
@return 是否是跳转响应
*/
func IsRedirectErr(err string) bool {
	erridx := strings.LastIndexByte(err, ':') + 2
	return erridx >= 2 && erridx < len(err) && err[erridx:] == REDIRECT_ERR.Error()
}

