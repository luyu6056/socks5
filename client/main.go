package main

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"

	"net/http"
	_ "net/http/pprof"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/luyu6056/gnet"

	"github.com/luyu6056/tls"
)

const (
	headlen         = 3 //1cmd2fd
	maxPlaintext    = 16384
	outdelay        = time.Millisecond * 2
	maxCiphertext   = maxPlaintext + 2048
	initWindowsSize = maxPlaintext * 20
	writeDeadline   = time.Second * 5
)
const (
	cmd_none        = iota
	cmd_getfd       //请求fd
	cmd_fd          //返回fd
	cmd_msg         //发送消息
	cmd_msgend      //消息尾
	cmd_msgrec      //确认消息
	cmd_msgresend   //重发消息
	cmd_deletefd    //删除fd资源
	cmd_msgresendno //重发整条msgno
	cmd_windowsupdate
	cmd_ping //请求ping
	cmd_pong //返回pong
	udpcheckIn
	udpcheckOut
	udpcheckMsg
	udpcheckRecno
	cmd_deleteIp //重启要求删除远程资源
	cmd_reg
)

var cmdToName = map[uint8]string{
	cmd_none:          "cmd_none",
	cmd_getfd:         "cmd_getfd",
	cmd_fd:            "cmd_fd",
	cmd_msg:           "cmd_msg",
	cmd_msgend:        "cmd_msgend",
	cmd_msgrec:        "cmd_msgrec",
	cmd_msgresend:     "cmd_msgresend",
	cmd_deletefd:      "cmd_deletefd",
	cmd_msgresendno:   "cmd_msgresendno",
	cmd_windowsupdate: "cmd_windowsupdate",
	cmd_ping:          "cmd_ping",
	cmd_pong:          "cmd_pong",
	udpcheckIn:        "udpcheckIn",
	udpcheckOut:       "udpcheckOut",
	udpcheckMsg:       "udpcheckMsg",
	udpcheckRecno:     "udpcheckRecno",
	cmd_deleteIp:      "cmd_deleteIp",
	cmd_reg:           "cmd_reg",
}

const (
	statusOFF = 0
	statusON  = 1
)

var (
	socks5_auth            string = string([]byte{5, 1, 0})
	socks5_authpwd         string = string([]byte{5, 1, 2})
	socks5_auth_sussces    []byte = []byte{5, 0}
	socks5_authpwd_sussces []byte = []byte{5, 2}
	serverAddr             []*addr
	protocolErr            = errors.New("protocolErr")
)

type ServerConn struct {
	conn                          net.Conn
	tlsconn                       *tls.Conn
	inboundBuffer, outboundBuffer *tls.MsgBuffer
	buf                           []byte
	outbufchan, outChan           chan *serverOutBuf
	inChan                        chan []byte
	regChan                       chan bool
	addr                          *addr
	pingtime, pongtime, rectime   int64
	status                        int
	tick                          *time.Ticker
	isPingConn                    bool //单独拉一个conn算窗口
	index                         int
}
type serverOutBuf struct {
	buf *tls.MsgBuffer
	c   *Conn
}
type Conn struct {
	windows_size int64
	remote       int32
	auth         int
	server       *ServerConn
	fd           [2]byte
	c            gnet.Conn
	wait         chan int
	close        string
}
type addr struct {
	addr string
	srtt float32 //单位 毫秒
	//bandwidth           uint64  //网络带宽 单位 字节/秒
	windows_update_size uint64
}

const (
	connWaitok = iota
	connWaitclose
	serverNum       = 4 //有效的连接数量
	connAuthClose   = 0
	connAuthNone    = 1
	connAuthPw      = 2
	connAuthOk      = 3
	connAuthMessage = 4
	connRemoteClose = 0
	connRemoteOpen  = 1
)

type httpServer struct {
	netchan []*ServerConn
	*gnet.EventServer
	addr string
}
type fdsort []*Conn

func (s fdsort) Len() int {
	return len(s)
}
func (s fdsort) Less(i, j int) bool {
	return uint16(s[i].fd[0])+uint16(s[i].fd[1])<<8 < uint16(s[j].fd[0])+uint16(s[j].fd[1])<<8
}
func (s fdsort) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

var (
	deleteIp   int32
	networkMac string
	fd_m       sync.Map
	fd         uint32
)

func main() {
	rand.Seed(time.Now().Unix())
	interfaces, err := net.Interfaces()
	for _, inter := range interfaces {
		networkMac = inter.HardwareAddr.String()
		if networkMac != "" {
			break
		}
	}
	if err != nil || networkMac == "" {
		panic("无法获取网卡mac")
	}
	networkMac += strconv.Itoa(rand.Int())
	hs := &httpServer{addr: "tcp://0.0.0.0:10800"}
	go func() {

		err := http.ListenAndServe("0.0.0.0:8081", nil)
		if err != nil {
			http.ListenAndServe("0.0.0.0:8082", nil)
		}

	}()
	//连接服务器，设置srtt为0（初始值,,默认初始窗口值,此处ip修改为server监听的ip端口
	serverAddr = []*addr{
		{"127.0.0.1:3306", 0, initWindowsSize},
	}

	for i := 0; i < serverNum*len(serverAddr); i++ {
		server := &ServerConn{index: i, inboundBuffer: &tls.MsgBuffer{}, outboundBuffer: &tls.MsgBuffer{}, addr: serverAddr[i%len(serverAddr)], tick: time.NewTicker(time.Second * 10), regChan: make(chan bool, 1)}
		server.buf = make([]byte, maxCiphertext)
		hs.netchan = append(hs.netchan, server)
		server.regChan <- true
		server.handle()

	}

	gnet.Serve(hs, hs.addr, gnet.WithLoopNum(4), gnet.WithReusePort(true), gnet.WithTCPKeepAlive(time.Second*600), gnet.WithCodec(&limitcodec{}), gnet.WithOutbuf(64), gnet.WithTicker(true), gnet.WithTCPNoDelay(true))
}
func (hs *httpServer) OnInitComplete(srv gnet.Server) (action gnet.Action) {
	fmt.Println("listen", hs.addr, srv.NumEventLoop)
	return
}
func (hs *httpServer) Tick() (delay time.Duration, action gnet.Action) {
	fd_m.Range(func(k, v interface{}) bool {

		conn := v.(*Conn)
		windows_update_size := int64(conn.server.addr.windows_update_size)
		size := windows_update_size - conn.windows_size
		if size > 0 {
			atomic.AddInt64(&conn.windows_size, size)
		} else {
			size = 0
		}

		b := <-conn.server.outbufchan
		buf := b.buf.Make(11)
		b.c = nil
		buf[0] = cmd_windowsupdate
		buf[1] = conn.fd[0]
		buf[2] = conn.fd[1]
		buf[3] = byte(size)
		buf[4] = byte(size >> 8)
		buf[5] = byte(size >> 16)
		buf[6] = byte(size >> 24)
		buf[7] = byte(size >> 32)
		buf[8] = byte(size >> 40)
		buf[9] = byte(size >> 48)
		buf[10] = byte(size >> 56)
		conn.server.outChan <- b

		return true
	})
	return time.Second * 10, gnet.None
}

var r = 1

func (hs *httpServer) OnOpened(c gnet.Conn) (out []byte, action gnet.Action) {
	conn := &Conn{}
	conn.wait = make(chan int, 1)
	conn.auth = connAuthNone
	conn.remote = connRemoteClose
	id := -1
	for n := 0; n < 60 && id == -1; n++ {
		r++
		srtt := float32(99999999)
		index := r % serverNum * len(serverAddr)
		for i := 0; i < len(serverAddr); i++ {
			if server := hs.netchan[index+i]; server.status == statusON && server.addr.srtt < srtt {
				srtt = server.addr.srtt
				id = index + i
			} else {
				//fmt.Printf("序号%d status:%v  srtt:%v \r\n",index+i, server.status,server.addr.srtt)
			}

		}
		if id == -1 {
			time.Sleep(time.Second)
		}

	}
	if id == -1 {
		return nil, gnet.Close
	}
	//r++

	conn.server = hs.netchan[id%serverNum]
	conn.c = c
	conn.windows_size = 0
	conn.wait <- connWaitok
	c.SetContext(conn)

	return
}

func (hs *httpServer) OnClosed(c gnet.Conn, err error) (action gnet.Action) {
	if conn, ok := c.Context().(*Conn); ok {
		<-conn.wait
		conn.wait <- connWaitclose
		conn.auth = connAuthClose
		fd_m.Delete(conn.fd)
		c.SetContext(nil)
		if conn.close == "" {
			conn.close = "未知关闭"
		}

		if conn.remote == connRemoteOpen {
			conn.remote = connRemoteClose
			conn.Remoteclose()
		}

	}
	return
}

func (hs *httpServer) React(data []byte, c gnet.Conn) (action gnet.Action) {

	conn, ok := c.Context().(*Conn)
	if !ok {
		return gnet.Close
	}

	switch conn.auth {
	case connAuthNone:
		if len(data) > 2 {
			if Bytes2str(data[:3]) == socks5_auth {
				c.FlushWrite(socks5_auth_sussces)
				conn.auth = connAuthOk
			}
			if Bytes2str(data[:3]) == socks5_authpwd {
				c.FlushWrite(socks5_authpwd_sussces)
				conn.auth = connAuthPw
			}
		}
	case connAuthPw:
		c.FlushWrite([]byte{1, 0})
		conn.auth = connAuthOk
	case connAuthOk:

		switch data[3] {
		case 1: //ipv4
			str := make([][]byte, 4)
			for k, v := range data[4:8] {
				str[k] = []byte(strconv.Itoa(int(v)))
			}

			conn.getfd(append(bytes.Join(str, []byte{46}), data[len(data)-2:]...))
			conn.auth = connAuthMessage
			c.FlushWrite([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		case 3: //域名
			conn.getfd(data[5:])
			conn.auth = connAuthMessage
			c.FlushWrite([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		case 4: //ipv6
		}
	case connAuthMessage:
		b := <-conn.server.outbufchan
		b.c = conn
		buf := b.buf.Make(headlen + len(data) + 8)
		buf[0] = cmd_msg //数据包
		buf[1] = conn.fd[0]
		buf[2] = conn.fd[1]
		//binary.LittleEndian.PutUint32(outbuf[5:], crc32.ChecksumIEEE(data)+conn.msgno)
		//conn.msgno++

		windows_update_size := conn.server.addr.windows_update_size
		var new_size int64
		if new_size = int64(windows_update_size) - conn.windows_size; new_size > 0 { //扩大窗口
			atomic.AddInt64(&conn.windows_size, new_size)

		} else {
			new_size = 0
		}
		buf[3] = byte(new_size)
		buf[4] = byte(new_size >> 8)
		buf[5] = byte(new_size >> 16)
		buf[6] = byte(new_size >> 24)
		buf[7] = byte(new_size >> 32)
		buf[8] = byte(new_size >> 40)
		buf[9] = byte(new_size >> 48)
		buf[10] = byte(new_size >> 56)
		copy(buf[headlen+8:], data) //消息内容
		conn.server.outChan <- b
	}

	return
}

func (conn *Conn) getfd(data []byte) {
	b := <-conn.server.outbufchan
	buf := b.buf.Make(headlen + len(data))
	b.c = conn
	buf[0] = cmd_getfd //注册fd值
	f := uint16(atomic.AddUint32(&fd, 1))
	for _, ok := fd_m.Load(f); ok; _, ok = fd_m.Load(f) {
		f = uint16(atomic.AddUint32(&fd, 1))
	}

	conn.fd[0] = byte(f)
	conn.fd[1] = byte(f >> 8)
	fd_m.Store(conn.fd, conn)
	buf[1] = conn.fd[0]
	buf[2] = conn.fd[1]
	copy(buf[headlen:], data)
	conn.remote = connRemoteOpen
	conn.server.outChan <- b
}

func Bytes2str(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func (server *ServerConn) handleMessage() (err error) {

	server.tick.Reset(time.Second * 30)
	defer func() {
		server.status = statusOFF
		server.regChan <- true
		fmt.Println("exit", err)

	}()
	buf1 := make([]byte, maxPlaintext)
	buf2 := make([]byte, maxPlaintext)
	m := uint8(0)
	for {
		server.conn.SetReadDeadline(time.Now().Add(writeDeadline))
		n, err := server.conn.Read(server.buf)
		if err != nil {
			if strings.Contains(err.Error(), "i/o timeout") {
				continue
			}
			return err
		}
		server.tlsconn.RawWrite(server.buf[:n])
		for err = server.tlsconn.ReadFrame(); err == nil && server.inboundBuffer.Len() > 0; err = server.tlsconn.ReadFrame() {
			m++
			if m%2 == 1 {
				copy(buf1, server.inboundBuffer.Bytes())
				server.inChan <- buf1[:server.inboundBuffer.Len()]
			} else {
				copy(buf2, server.inboundBuffer.Bytes())
				server.inChan <- buf2[:server.inboundBuffer.Len()]
			}
			server.inboundBuffer.Reset()
			server.rectime = time.Now().Unix()
		}
		if err != nil && err != io.EOF {
			return err
		}

	}
}
func (server *ServerConn) do(msg []byte) {
	var conn *Conn
	switch msg[0] {
	case cmd_fd:
		if v, ok := fd_m.Load([2]byte{msg[1], msg[2]}); ok {
			conn = v.(*Conn)
			flag := <-conn.wait
			defer func() { conn.wait <- flag }()
			if flag == connWaitclose {
				return
			}

		} else {
			return
		}
		if msg[3] == 1 {
			conn.auth = 3
			conn.c.FlushWrite([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		} else {
			conn.c.FlushWrite([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			conn.c.Close()
		}

	case cmd_deletefd:
		if v, ok := fd_m.Load([2]byte{msg[1], msg[2]}); ok {
			conn = v.(*Conn)
			flag := <-conn.wait
			defer func() { conn.wait <- flag }()
			if flag == connWaitclose {
				return
			}
		} else {
			return
		}
		conn.close = "服务器要求远程关闭"
		conn.remote = connRemoteClose
		conn.c.Close()
		return
	case cmd_msg:

		if v, ok := fd_m.Load([2]byte{msg[1], msg[2]}); ok {
			conn = v.(*Conn)
		} else {
			return
		}
		conn.c.FlushWrite(msg[headlen:])
		windows_size := atomic.AddInt64(&conn.windows_size, int64(headlen-len(msg)))
		windows_update_size := int64(conn.server.addr.windows_update_size)

		if windows_size < windows_update_size/2 { //扩大窗口
			if size := windows_update_size - conn.windows_size; size > 0 {
				atomic.AddInt64(&conn.windows_size, size)
				go func() {
					b := <-server.outbufchan
					buf := b.buf.Make(11)
					b.c = nil
					buf[0] = cmd_windowsupdate
					buf[1] = conn.fd[0]
					buf[2] = conn.fd[1]
					buf[3] = byte(size & 255)
					buf[4] = byte(size >> 8 & 255)
					buf[5] = byte(size >> 16 & 255)
					buf[6] = byte(size >> 24 & 255)
					buf[7] = byte(size >> 32 & 255)
					buf[8] = byte(size >> 40 & 255)
					buf[9] = byte(size >> 48 & 255)
					buf[10] = byte(size >> 56 & 255)
					server.outChan <- b
				}()
			}
		}

	case cmd_pong:
		pingtime := int64(msg[1]) | int64(msg[2])<<8 | int64(msg[3])<<16 | int64(msg[4])<<24 | int64(msg[5])<<32 | int64(msg[6])<<40 | int64(msg[7])<<48 | int64(msg[8])<<56

		if pingtime != server.pingtime {
			return
		}
		server.pongtime = time.Now().Unix()
		if server.isPingConn {
			fmt.Println(time.Now().Format("2006-01-02 15:04:05"))
			if server.addr.srtt == 0 {
				server.addr.srtt = float32((server.pongtime - pingtime) / 1e6)
			} else {
				server.getRtt(server.pongtime - pingtime)
			}
		}

	case cmd_deleteIp:
		if !atomic.CompareAndSwapInt32(&deleteIp, 0, 1) { //第一次连接服务器会返回一次删除，无视第一次

			fd_m.Range(func(k, v interface{}) bool {
				v.(*Conn).c.Close()
				fd_m.Delete(k)
				return true

			})
		}

	case cmd_msgresendno:
	case cmd_reg, cmd_none:
	default:
		fmt.Println("错误", msg[0])
		panic("errormsg")

	}
}
func (server *ServerConn) getRtt(timediff int64) {
	/*server.addr.srtt = server.addr.srtt + 0.125*(float32(timediff)/1e6-server.addr.srtt) //srtt = srtt + 0.125(rtt-srtt)
	//计算一个新的窗口值，由于rtt不是实时获取，不能做那种实时的变动的rtt窗口
	server.addr.windows_update_size = server.addr.bandwidth / 1000 * uint64(server.addr.srtt) / 100
	fmt.Println(server.addr.windows_update_size)
	if server.addr.windows_update_size < 163840 {
		server.addr.windows_update_size = 163840
	}*/

}

func (server *ServerConn) reg() error {
	server.pingtime = 0
	server.pongtime = 0
	if server.tlsconn != nil {
		server.tlsconn = nil
	}
	if server.conn != nil {
		server.conn.Close()
	}
	server.tick.Stop()
	time.Sleep(time.Second * 5) //等5秒后连接，避免频繁连接

	var err error

	server.conn, err = net.Dial("tcp", server.addr.addr)
	if err != nil {

		return err

	}
	server.inboundBuffer.Reset()
	server.conn.SetReadDeadline(time.Now().Add(writeDeadline))
	buf := make([]byte, 2048)
	n, err := server.conn.Read(buf)
	if err != nil {
		log.Println("这里4", err)
		return err
	}
	if n < 4 {
		return errors.New("msg too short")
	}
	server.inboundBuffer.Write(buf[:n])
	b := server.inboundBuffer.Next(4)
	if b[3] != 0 {
		return protocolErr
	}
	msglen := int(b[0]) | int(b[1])<<8 | int(b[2])<<16
	for olen := server.inboundBuffer.Len(); olen < msglen; olen = server.inboundBuffer.Len() {
		buf = make([]byte, msglen)
		n, err := server.conn.Read(buf)
		if err != nil {
			log.Println("这里3")
			return err
		}
		server.inboundBuffer.Write(buf[:n])
	}
	if server.inboundBuffer.Next(1)[0] != 10 {
		return protocolErr
	}
	server.inboundBuffer.Reset()
	server.outboundBuffer.Reset()
	//不解析了，直接返回ssl握手
	server.conn.Write([]byte{32, 0, 0, 1, 8, 138, 8, 0, 255, 255, 255, 0, 33, 53, 45, 49, 48, 46, 53, 46, 49, 45, 77, 97, 114, 105, 97, 68, 66, 0, 64, 1, 0, 0, 67, 66})
	server.tlsconn = tls.Client(server, server.inboundBuffer, server.outboundBuffer, tlsconfig.Clone())

	if err := server.tlsconn.Handshake(); err != nil {
		return errors.New("tls握手失败" + err.Error())
	}

	for !server.tlsconn.HandshakeComplete() {
		for data := server.tlsconn.RawData(); len(data) < 5 || int(data[3])<<8|int(data[4])+5 > len(data); data = server.tlsconn.RawData() {
			n, err := server.conn.Read(server.buf)
			if err != nil {
				log.Println("这里2")
				return err
			}
			server.tlsconn.RawWrite(server.buf[:n])
		}

		if err := server.tlsconn.Handshake(); err != nil {
			return err
		}
	}
	mac := []byte(networkMac)
	b = make([]byte, len(mac)+1)
	b[0] = cmd_reg
	copy(b[1:], mac)
	server.tlsconn.Write(b)
	server.conn.Write(server.outboundBuffer.Bytes())
	server.outboundBuffer.Reset()
	b = make([]byte, maxPlaintext)
	b[0] = 0
	for i := 0; i < 7; i++ {
		server.tlsconn.Write(b)
		server.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
		_, err = server.conn.Write(server.outboundBuffer.Bytes())
		server.outboundBuffer.Reset()
		if err != nil {
			log.Println("这里1", err)
			return err
		}
	}
	server.status = statusON
	fmt.Printf("connect to %s success\r\n", server.addr.addr)
	return nil
}

func (server *ServerConn) handle() {
	bufnum := 64
	server.outChan = make(chan *serverOutBuf, bufnum)
	server.inChan = make(chan []byte)
	server.outbufchan = make(chan *serverOutBuf, bufnum)
	for i := 0; i < bufnum; i++ {
		server.outbufchan <- &serverOutBuf{buf: &tls.MsgBuffer{}}
	}

	pingdata := make([]byte, 9)

	pingfunc := func() {
		now := time.Now()
		if server.pingtime > server.pongtime && server.pingtime > server.rectime {
			fmt.Println(time.Now().Format("2006-01-02 15:04:05"), server.index, "超时", server.pingtime, server.pongtime, server.rectime)
			server.conn.Close()
		}
		server.pingtime = now.Unix()
		if server.pongtime == 0 {
			server.pongtime = server.pingtime
		}
		pingtime := uint64(server.pingtime)
		pingdata[0] = cmd_ping
		pingdata[1] = byte(pingtime & 255)
		pingdata[2] = byte(pingtime >> 8 & 255)
		pingdata[3] = byte(pingtime >> 16 & 255)
		pingdata[4] = byte(pingtime >> 24 & 255)
		pingdata[5] = byte(pingtime >> 32 & 255)
		pingdata[6] = byte(pingtime >> 40 & 255)
		pingdata[7] = byte(pingtime >> 48 & 255)
		pingdata[8] = byte(pingtime >> 56 & 255)
		server.tlsconn.Write(pingdata)
		server.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
		_, err := server.conn.Write(server.outboundBuffer.Bytes())
		server.outboundBuffer.Reset()
		if err != nil {
			server.conn.Close()
		}

	}
	go func() {
		for {
			select {
			case <-server.regChan:
			reConnet:
				err := server.reg()
				if err != nil {
					goto reConnet
				} else {
					pingfunc()
					go server.handleMessage()
				}

			case b := <-server.inChan:
				server.do(b)
				for i := 0; i < len(server.inChan); i++ {
					server.do(<-server.inChan)
				}
			case b := <-server.outChan:
				if b.c != nil {
					flag := <-b.c.wait
					if flag == connWaitok {
						server.tlsconn.Write(b.buf.Bytes())
					}
					b.c.wait <- flag
					b.c = nil
				} else {
					server.tlsconn.Write(b.buf.Bytes())
				}

				b.buf.Reset()
				server.outbufchan <- b
				for i := 0; i < len(server.outChan); i++ {
					b := <-server.outChan
					if b.c != nil {
						flag := <-b.c.wait
						if flag == connWaitok {
							server.tlsconn.Write(b.buf.Bytes())
						}
						b.c.wait <- flag
						b.c = nil
					} else {
						server.tlsconn.Write(b.buf.Bytes())
					}
					b.buf.Reset()
					server.outbufchan <- b
				}
				server.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
				_, err := server.conn.Write(server.outboundBuffer.Bytes())
				server.outboundBuffer.Reset()
				if err != nil {
					server.conn.Close()
				}
			case <-server.tick.C:
				//尽量清空消息以接收pong避免频繁超时断连
				for i := 0; i < len(server.inChan); i++ {
					server.do(<-server.inChan)
				}
				pingfunc()

			}
		}
	}()

}

func (conn *Conn) Remoteclose() {
	if conn.server.tlsconn == nil || !conn.server.tlsconn.HandshakeComplete() {
		return
	}
	conn.close = "本地要求远程关闭"
	b := <-conn.server.outbufchan
	buf := b.buf.Make(3)
	b.c = nil
	buf[0] = cmd_deletefd
	buf[1] = conn.fd[0]
	buf[2] = conn.fd[1]
	conn.server.outChan <- b
}

var tlsconfig *tls.Config

func init() {
	cert, err := tls.X509KeyPair([]byte(rsaCertPEM), []byte(rsaKeyPEM))
	if err != nil {
		return

	}
	certPool := x509.NewCertPool()

	if ok := certPool.AppendCertsFromPEM([]byte(caPem)); !ok {
		return
	}
	tlsconfig = &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		RootCAs:            certPool,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites:       []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
	}

}

//内置证书
var rsaCertPEM = `-----BEGIN CERTIFICATE-----
MIIBnjCCAUUCFC/GPrKj+VjVhhpRodwdOY3dYj7/MAoGCCqGSM49BAMCMFIxCzAJ
BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l
dCBXaWRnaXRzIFB0eSBMdGQxCzAJBgNVBAMMAnl5MB4XDTIwMDMyNjA5MTgwOVoX
DTMwMDMyNDA5MTgwOVowUjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3Rh
dGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDELMAkGA1UEAwwC
eXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ9I8GAtuOLGwfO8RHG7pnz8ZLk
HZk7QvWB754Fztv6I541qX6VHB1ErrcOrbiuo8Dj9IOeCcagwE9EC3YKnQIXMAoG
CCqGSM49BAMCA0cAMEQCIBjfT9q9x2hymyLZl08Cwaok/GdQ52gmZbtivm8AHB7Z
AiA0O8k01K9LRofBeEsWLI+NUZbhR9btzQNSrSLu9gSq5g==
-----END CERTIFICATE-----
`

var rsaKeyPEM = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOUDS2p8gdMtZY9kjda5dypRIPNO0uMCjFfYbGhZIsNKoAoGCCqGSM49
AwEHoUQDQgAEPSPBgLbjixsHzvERxu6Z8/GS5B2ZO0L1ge+eBc7b+iOeNal+lRwd
RK63Dq24rqPA4/SDngnGoMBPRAt2Cp0CFw==
-----END EC PRIVATE KEY-----
`
var caPem = `-----BEGIN CERTIFICATE-----
MIIBnjCCAUUCFHAHUvw4r3xKuHV94WaoB00KqFSTMAoGCCqGSM49BAMCMFIxCzAJ
BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l
dCBXaWRnaXRzIFB0eSBMdGQxCzAJBgNVBAMMAnl5MB4XDTIwMDMyNjA5MTQ0NloX
DTMwMDMyNDA5MTQ0NlowUjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3Rh
dGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDELMAkGA1UEAwwC
eXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARTS15wDJVQiERF3YqUNsgjnI80
iuBZ3e5e5pIJPvaZddk4ot6CsF4u9tkXLCRh7dcDMR+rh8Tm9QfuZv9P5choMAoG
CCqGSM49BAMCA0cAMEQCIEtdHtyiJiFYb3bJCiw/F31pyw65/SXzFuJaA/50NDiR
AiAW6CelTT+oJqBlj4awZ37Y4mJNaR9k2GYYZk8dIhclYg==
-----END CERTIFICATE-----
`

type limitcodec struct {
}

func (code *limitcodec) Encode(c gnet.Conn, buf []byte) ([]byte, error) {
	return buf, nil
}

func (code *limitcodec) Decode(c gnet.Conn) ([]byte, error) {
	if c.BufferLength() > 0 {
		n, buf := c.ReadN(maxPlaintext - headlen - 8)
		c.ShiftN(n)
		return buf, nil
	}
	return nil, nil

}
func (server *ServerConn) Write(b []byte) (int, error) {
	if server.conn == nil {
		return 0, io.EOF
	}
	var err error
	if server.tlsconn != nil {
		server.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
		_, err = server.conn.Write(server.outboundBuffer.Bytes())
		server.outboundBuffer.Reset()
	} else {
		server.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
		_, err = server.conn.Write(b)

	}

	return len(b), err
}

func (server *ServerConn) BufferLength() int {
	return server.inboundBuffer.Len()
}
func (server *ServerConn) Close() error {
	return nil
}
func (server *ServerConn) Context() interface{} {
	return nil
}
func (server *ServerConn) LocalAddr() net.Addr {
	return server.conn.LocalAddr()
}
func (server *ServerConn) RemoteAddr() net.Addr {
	return server.conn.RemoteAddr()
}
func (server *ServerConn) Read() []byte {
	return server.inboundBuffer.Bytes()
}
func (server *ServerConn) ReadN(n int) (int, []byte) {
	buf := server.inboundBuffer.PreBytes(n)
	return len(buf), buf
}
func (server *ServerConn) ResetBuffer() {
	server.inboundBuffer.Reset()
}
func (server *ServerConn) SendTo(b []byte) {
	server.conn.Write(b)
}
func (server *ServerConn) SetContext(i interface{}) {}
func (server *ServerConn) ShiftN(n int) int {
	server.inboundBuffer.Next(n)
	return n
}
func (server *ServerConn) Wake() {}
