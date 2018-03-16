package constValue

import (
	"errors"
)

const (
	PROXY_PORT = 8081
	CERTOUTS_PATH = "./certs/outs/"
	CERT_NODEID = 0
	EXPIRE_TIME = 24 * 3600 //秒
)

var (
	REDIRECT_ERR = errors.New("REDI_ERR")
)

