package constValue

import (
	"errors"
	"time"
)

const (
	PROXY_PORT = 8081
	CERTOUTS_PATH = "./certs/outs/"
	CERT_NODEID = 0
	EXPIRE_TIME = 24 * 3600 //秒
	TLS_READ_TIMEOUT = 5 * time.Millisecond
)

var (
	REDIRECT_ERR = errors.New("REDI_ERR")
	HTTP_CLOSE_ERR = errors.New("CLOSE_ERR")
	TIME_ZERO = time.Time{}
)

