package quic_client

import (
	"github.com/lucas-clemente/quic-go/h2quic"
	"net/http"
)

var (
	rt = &h2quic.RoundTripper{}
	Quic_cli = &http.Client{Transport: rt}
)

