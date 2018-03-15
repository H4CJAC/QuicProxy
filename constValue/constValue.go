package constValue

import (
	"time"
	"errors"
)

const (
	BUFFER_SIZE = 32 * 1024
	PROXY_PORT = 8081
	WAIT_COUNT = 5
	WAIT_TIME = 2 * time.Second
	CERTOUTS_PATH = "./certs/outs/"
)

var (
	REDIRECT_ERR = errors.New("REDI_ERR")
)

