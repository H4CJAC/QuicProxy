package constValue

import (
	"errors"
	"time"
	"net/http"
	"golang.org/x/net/http2"
	"strings"
)

const (
	PROXY_PORT = 8081
	CERTOUTS_PATH = "./certs/outs/"
	CERT_NODEID = 0
	EXPIRE_TIME = 24 * 3600 //秒
	QUIC_DO_TIMEOUT = 30 * time.Second
	BROKEN_STEP = 20 * time.Second
)

var (
	REDIRECT_ERR = errors.New("REDI_ERR")
	HTTP_CLOSE_ERR = errors.New("CLOSE_ERR")
	TIMEOUT_ERR = errors.New("TIMEOUT_ERR")
	BROKEN_ERR = errors.New("BROKEN_ERR")
	TIME_ZERO = time.Time{}
	H2_cli = &http.Client{Transport: &http2.Transport{AllowHTTP: true}}
)

func IsRedirectErr(err string) bool {
	erridx := strings.LastIndexByte(err, ':') + 2
	return erridx >= 2 && erridx < len(err) && err[erridx:] == REDIRECT_ERR.Error()
}

