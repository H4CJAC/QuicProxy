package quicAddrs

import (
	"strings"
	"time"
	"log"
	"GoQuicProxy/constValue"
	"sync"
	"math"
)

var (
	quic_support_map = quicSupportMap{mp: make(map[string]*addrInfo), mtx: sync.RWMutex{}}
)

type quicSupportMap struct {
	mp map[string]*addrInfo
	mtx sync.RWMutex
}

type addrInfo struct {
	quic_support bool //是否支持QUIC
	expire_time int64 //QUIC支持性信息超时时间，单位毫秒
	broken_time int64 //故障时间，单位毫秒
	broken_count int16 //故障次数
	port string //目的网站QUIC端口
	mtx sync.RWMutex
}

/*
获取QUIC支持性信息对象
@param addr 目的网站地址
@return (QUIC支持性信息对象, 是否存在QUIC支持性信息)
*/
func (m *quicSupportMap) get(addr string) (*addrInfo, bool) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	info, ok := m.mp[addr]
	return info, ok
}

/*
添加QUIC支持性信息对象
@param addr 目的网站地址
@param info QUIC支持性信息对象
@return
*/
func (m *quicSupportMap) add(addr string, info *addrInfo) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.mp[addr] = info
}

/*
重置故障状态函数
@param address 目的网站地址
@return
 */
func ResetBroken(address string) {
	a, ok := quic_support_map.get(address)
	if !ok {
		return
	}
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.broken_count = 0
	log.Println("reset broken:", address)
}

/*
故障次数增加处理函数
@param address 目的网站地址
@return
 */
func IncBroken(address string) {
	a, ok := quic_support_map.get(address)
	if !ok {
		return
	}
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if a.broken_count < 1 {
		a.broken_count = 1
	}else {
		if a.broken_count < (1 << 14) {
			a.broken_count <<= 1
		}else {
			a.broken_count = math.MaxInt16
		}
	}
	a.broken_time = time.Now().Unix() + int64(a.broken_count) * int64(constValue.BROKEN_STEP.Seconds())
	log.Println("broken:", a.broken_time, a.broken_count)
}

/*
检测故障状态函数
@param address 目的网站地址
@return (是否故障, （前个参数为false时有效）是否最近故障)
 */
func IsBroken(address string) (bool, bool) { //isbroken, countlargerthanzero
	a, ok := quic_support_map.get(address)
	if !ok {
		log.Println("isbroken:", address)
		return true, false
	}
	a.mtx.RLock()
	defer a.mtx.RUnlock()
	if a.broken_time < time.Now().Unix() {
		return false, a.broken_count > 0
	}
	log.Println("isbroken:", address)
	return true, a.broken_count > 0
}

/*
QUIC支持检测函数
@param address 目的网站地址
@param now_time 当前时间戳
@return (目的网站是否支持QUIC协议, 目的网站部署QUIC的端口号)
 */
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

/*
检测目的网站是否支持QUIC协议
@param address 目的网站地址
@param now_time 当前时间戳
@return (是否支持QUIC协议, QUIC端口)
*/
func CheckAddr(address string, now_time int64) (bool, string) {
	//存入缓存
	addr_info := &addrInfo{expire_time: now_time + constValue.EXPIRE_TIME, mtx: sync.RWMutex{}}
	res, err := constValue.H2_cli.Head(address)
	if err != nil {
		log.Println(err)
		//res != nil... 避免EOF错误导致quic识别错误，识别机制容错性有待改善
		if !(constValue.IsRedirectErr(err.Error()) || (res != nil && res.Header != nil)) {
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
	//s_off == e_off不处理
	if s_off >= e_off || e_off > len(alt_svc) {
		addr_info.quic_support = false
		quic_support_map.add(address, addr_info)
		return false, ""
	}

	//alt-svc = url:port不处理
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