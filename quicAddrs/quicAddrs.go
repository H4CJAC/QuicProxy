package quicAddrs

import (
	"strings"
	"net/http"
	"time"
	"log"
	"GoQuicProxy/constValue"
)

var (
	quicSupportMap = make(map[string]*addrInfo)
)

type addrInfo struct {
	quic_support bool
	expire_time int64
	port string
}

//是否支持quic
func IsQuicSupported(address string) (bool, string) {
	addr_info, ok := quicSupportMap[address]
	now_time := time.Now().Unix()
	//存在缓存中并未过期
	if ok && (addr_info.expire_time >= now_time) {
		log.Println(addr_info.quic_support, address)
		return addr_info.quic_support, addr_info.port
	}
	return CheckAddr(address, now_time)
}

func CheckAddr(address string, now_time int64) (bool, string) {
	//存入缓存
	quicSupportMap[address] = &addrInfo{expire_time: now_time + constValue.EXPIRE_TIME}
	addr_info, _ := quicSupportMap[address]
	res, err := http.DefaultClient.Head(address)
	if err != nil {
		log.Println(err)
		addr_info.quic_support = false
		return false, ""
	}
	alt_svc := res.Header.Get("Alt-Svc")
	if alt_svc == "" {
		addr_info.quic_support = false
		return false, ""
	}
	s_off := strings.Index(alt_svc, "quic=\"") + 6
	if s_off < 6 || s_off >= len(alt_svc) {
		addr_info.quic_support = false
		return false, ""
	}
	e_off := strings.IndexByte(alt_svc[s_off:], '"') + s_off
	if s_off > e_off || e_off > len(alt_svc) {
		addr_info.quic_support = false
		return false, ""
	}
	addr_info.quic_support = true
	addr_info.port = alt_svc[s_off:e_off]
	res.Body.Close()
	return true, addr_info.port
}