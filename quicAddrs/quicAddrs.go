package quicAddrs

import (
	"strings"
	"time"
	"log"
	"GoQuicProxy/constValue"
	"sync"
)

var (
	quic_support_map = quicSupportMap{mp: make(map[string]*addrInfo), mtx: sync.RWMutex{}}
)

type quicSupportMap struct {
	mp map[string]*addrInfo
	mtx sync.RWMutex
}

type addrInfo struct {
	quic_support bool
	expire_time int64
	port string
}

func (m *quicSupportMap) get(addr string) (*addrInfo, bool) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	info, ok := m.mp[addr]
	return info, ok
}

func (m *quicSupportMap) add(addr string, info *addrInfo) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.mp[addr] = info
}

//是否支持quic
func IsQuicSupported(address string) (bool, string) {
	log.Println(len(quic_support_map.mp)) /////////////
	addr_info, ok := quic_support_map.get(address)
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
	addr_info := &addrInfo{expire_time: now_time + constValue.EXPIRE_TIME}
	res, err := constValue.H2_cli.Head(address)
	if err != nil {
		log.Println(err)
		if !constValue.IsRedirectErr(err.Error()) {
			addr_info.quic_support = false
			quic_support_map.add(address, addr_info)
			return false, ""
		}
	}

	defer res.Body.Close()

	alt_svc := res.Header.Get("Alt-Svc")
	if alt_svc == "" {
		addr_info.quic_support = false
		quic_support_map.add(address, addr_info)
		return false, ""
	}
	s_off := strings.Index(alt_svc, "quic=\"") + 6
	if s_off < 6 || s_off >= len(alt_svc) {
		addr_info.quic_support = false
		quic_support_map.add(address, addr_info)
		return false, ""
	}
	e_off := strings.IndexByte(alt_svc[s_off:], '"') + s_off
	//s_off == e_off means nothing
	if s_off >= e_off || e_off > len(alt_svc) {
		addr_info.quic_support = false
		quic_support_map.add(address, addr_info)
		return false, ""
	}

	/*alt-svc = url:port, leave url alone*/
	p_off := strings.IndexByte(alt_svc[s_off:e_off], ':')
	if p_off < 0 || p_off >= e_off - s_off {
		addr_info.quic_support = false
		quic_support_map.add(address, addr_info)
		return false, ""
	}
	s_off += p_off

	addr_info.quic_support = true
	addr_info.port = alt_svc[s_off:e_off]
	quic_support_map.add(address, addr_info)
	return true, addr_info.port
}