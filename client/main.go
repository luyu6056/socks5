package main

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"

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
	initWindowsSize = maxPlaintext * 40
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
	fd      uint32 //每个服务器链接最多只有65535个fd连接
	fd_m    *sync.Map
	conn    net.Conn
	tlsconn *tls.Conn

	inboundBuffer, outboundBuffer *tls.MsgBuffer
	buf                           []byte
	outbufchan, outChan           chan *tls.MsgBuffer
	wait, c                       chan int
	addr                          *addr
	pingtime                      int64
	pongtime                      int64
	status                        int
}
type Conn struct {
	windows_size int64
	auth         int
	server       *ServerConn
	fd           [2]byte
	c            gnet.Conn
	wait         chan int
	send         uint64
}
type addr struct {
	addr                string
	srtt                float32 //单位 毫秒
	bandwidth           uint64  //网络带宽 单位 字节/秒
	windows_update_size uint64
}

const (
	connWaitok = iota
	connWaitclose
	serverNum = 8 //有效的连接数量
)

func main() {
	go func() {
		err := http.ListenAndServe("0.0.0.0:8081", nil)
		if err != nil {
			http.ListenAndServe("0.0.0.0:8082", nil)
		}

	}()
	//连接服务器，设置srtt为0（初始值），设置带宽100M,默认初始窗口值,此处ip修改为server监听的ip端口
	serverAddr = []*addr{
		{"202.81.235.45:3306", 0, 100 * 1024 * 1024, initWindowsSize},
		{"202.81.235.51:3306", 0, 100 * 1024 * 1024, initWindowsSize},
		{"202.81.235.114:3306", 0, 100 * 1024 * 1024, initWindowsSize},
		{"202.81.231.131:3306", 0, 100 * 1024 * 1024, initWindowsSize},
	}
	http := &httpServer{addr: "tcp://0.0.0.0:10808"}
	for i := 0; i < serverNum*len(serverAddr); i++ {
		server := &ServerConn{fd_m: new(sync.Map), inboundBuffer: &tls.MsgBuffer{}, outboundBuffer: &tls.MsgBuffer{}, addr: serverAddr[i%len(serverAddr)]}
		server.buf = make([]byte, maxCiphertext)
		http.netchan = append(http.netchan, server)

		handleOut(server)
		go handleRemote(server)
	}
	for i := 0; i < len(serverAddr); i++ {
		server := &ServerConn{fd_m: new(sync.Map), inboundBuffer: &tls.MsgBuffer{}, outboundBuffer: &tls.MsgBuffer{}, addr: serverAddr[i%len(serverAddr)]}
		server.buf = make([]byte, maxCiphertext)

		go ping(server)
		go handleRemote(server)
	}

	gnet.Serve(http, http.addr, gnet.WithLoopNum(8), gnet.WithReusePort(true), gnet.WithTCPKeepAlive(time.Second*600), gnet.WithCodec(&limitcodec{}), gnet.WithOutbuf(64))
}
func (hs *httpServer) OnInitComplete(srv gnet.Server) (action gnet.Action) {
	fmt.Println("listen", hs.addr, srv.NumEventLoop)
	return
}

var conn_pool = &sync.Pool{
	New: func() interface{} {
		b := &Conn{}
		b.wait = make(chan int, 1)
		b.wait <- connWaitclose
		return b
	},
}
var r = 1

func (hs *httpServer) OnOpened(c gnet.Conn) (out []byte, action gnet.Action) {
	conn := conn_pool.Get().(*Conn)
	<-conn.wait
	conn.auth = 0

	id := -1
	for id == -1 {
		r++
		srtt := float32(99999999)
		index := r % serverNum * len(serverAddr)
		for i := 0; i < len(serverAddr); i++ {
			if server := hs.netchan[index+i]; server.status == statusON && server.addr.srtt < srtt {
				srtt = server.addr.srtt
				id = index + i
			}

		}
		if id == -1 {
			time.Sleep(time.Second)
		}

	}
	conn.server = hs.netchan[id]
	conn.c = c
	conn.windows_size = initWindowsSize
	conn.wait <- connWaitok
	c.SetContext(conn)
	return
}

func (hs *httpServer) OnClosed(c gnet.Conn, err error) (action gnet.Action) {
	if conn, ok := c.Context().(*Conn); ok {
		<-conn.wait
		conn.server.fd_m.Delete(conn.fd)
		c.SetContext(nil)
		if conn.auth == 3 {
			conn.Remoteclose()
		}
		conn.wait <- connWaitclose
		time.AfterFunc(time.Second, func() { conn_pool.Put(conn) })
	}
	return
}

func (hs *httpServer) React(data []byte, c gnet.Conn) (action gnet.Action) {

	conn := c.Context().(*Conn)

	switch conn.auth {
	case 0:
		if len(data) > 2 {
			if Bytes2str(data[:3]) == socks5_auth {
				c.AsyncWrite(socks5_auth_sussces)
				conn.auth = 2
			}
			if Bytes2str(data[:3]) == socks5_authpwd {
				c.AsyncWrite(socks5_authpwd_sussces)
				conn.auth = 1
			}
		}
	case 1:
		c.AsyncWrite([]byte{1, 0})
		conn.auth = 2
	case 2:

		switch data[3] {
		case 1: //ipv4
			str := make([][]byte, 4)
			for k, v := range data[4:8] {
				str[k] = []byte(strconv.Itoa(int(v)))
			}

			conn.getfd(append(bytes.Join(str, []byte{46}), data[len(data)-2:]...))
			conn.auth = 3
			c.AsyncWrite([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		case 3: //域名
			conn.getfd(data[5:])
			conn.auth = 3
			c.AsyncWrite([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		case 4: //ipv6
		}
	case 3:

		b := <-conn.server.outbufchan
		buf := b.Make(headlen + len(data) + 8)
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
		buf[3] = byte(new_size & 255)
		buf[4] = byte(new_size >> 8 & 255)
		buf[5] = byte(new_size >> 16 & 255)
		buf[6] = byte(new_size >> 24 & 255)
		buf[7] = byte(new_size >> 32 & 255)
		buf[8] = byte(new_size >> 40 & 255)
		buf[9] = byte(new_size >> 48 & 255)
		buf[10] = byte(new_size >> 54 & 255)
		copy(buf[headlen+8:], data) //消息内容
		conn.server.outChan <- b
	}

	return
}

type httpServer struct {
	netchan []*ServerConn
	*gnet.EventServer
	addr string
}

func (conn *Conn) getfd(data []byte) {

	b := <-conn.server.outbufchan
	buf := b.Make(headlen + len(data))

	buf[0] = cmd_getfd //注册fd值
	fd := uint16(atomic.AddUint32(&conn.server.fd, 1))
	conn.fd[0] = byte(fd)
	conn.fd[1] = byte(fd >> 8)
	conn.server.fd_m.Store(conn.fd, conn)
	buf[1] = conn.fd[0]
	buf[2] = conn.fd[1]
	copy(buf[headlen:], data)
	conn.server.outChan <- b
}

func Bytes2str(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func handleRemote(server *ServerConn) (err error) {
	//先发送注册消息
	defer func() {
		if server.status == statusON {
			server.wait <- 0
			server.status = statusOFF
		}

		if server.tlsconn != nil {
			server.tlsconn = nil
		}

		if server.conn != nil {
			server.conn.Close()
		}
		fmt.Println("exit", err)
		time.Sleep(time.Second * 10) //10秒后重试
		go handleRemote(server)
	}()
	if err = server.reg(); err != nil {
		return
	}
	//

	for {
		n, err := server.conn.Read(server.buf)
		if err != nil {
			fmt.Println("读错误1", err)
			return err
		}
		server.tlsconn.RawWrite(server.buf[:n])
		for err = server.tlsconn.ReadFrame(); err == nil && server.inboundBuffer.Len() > 0; err = server.tlsconn.ReadFrame() {
			server.do(server.inboundBuffer.Bytes())
			server.inboundBuffer.Reset()
		}
		if err != nil && err != io.EOF {
			fmt.Println("读错误2", err)
			return err
		}

	}
}
func (server *ServerConn) do(msg []byte) {
	var conn *Conn
	switch msg[0] {
	case cmd_fd:
		if v, ok := server.fd_m.Load([2]byte{msg[1], msg[2]}); ok {
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
			conn.c.AsyncWrite([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		} else {
			conn.c.AsyncWrite([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			conn.c.Close()
		}

	case cmd_deletefd:
		if v, ok := server.fd_m.Load([2]byte{msg[1], msg[2]}); ok {
			conn = v.(*Conn)
			flag := <-conn.wait
			defer func() { conn.wait <- flag }()
			if flag == connWaitclose {
				return
			}
		} else {
			return
		}
		conn.c.Close()
		return
	case cmd_msg:

		if v, ok := server.fd_m.Load([2]byte{msg[1], msg[2]}); ok {
			conn = v.(*Conn)
			flag := <-conn.wait
			defer func() { conn.wait <- flag }()
			if flag == connWaitclose {
				return
			}
		} else {
			return
		}
		conn.c.AsyncWrite(msg[headlen:])
		windows_size := atomic.AddInt64(&conn.windows_size, int64(headlen-len(msg)))
		windows_update_size := int64(conn.server.addr.windows_update_size)
		if windows_size < windows_update_size/2 { //扩大窗口
			if size := windows_update_size - conn.windows_size; size > 0 {
				atomic.AddInt64(&conn.windows_size, size)
				b := <-server.outbufchan
				buf := b.Make(11)
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
				buf[10] = byte(size >> 54 & 255)
				server.outChan <- b
			}
		}

	case cmd_pong:
		pingtime := int64(msg[1]) | int64(msg[2])<<8 | int64(msg[3])<<16 | int64(msg[4])<<24 | int64(msg[5])<<32 | int64(msg[6])<<40 | int64(msg[7])<<48 | int64(msg[8])<<54
		if pingtime != server.pingtime {
			return
		}
		if server.addr.srtt == 0 {
			server.addr.srtt = float32((time.Now().UnixNano() - pingtime) / 1e6)
		} else {
			server.getRtt(time.Now().UnixNano() - pingtime)

		}

	case cmd_msgresendno:
	case cmd_reg, cmd_none:
	default:
		fmt.Println("错误", msg[0])
		panic("errormsg")

	}
}
func (server *ServerConn) getRtt(timediff int64) {
	server.addr.srtt = server.addr.srtt + 0.125*(float32(timediff)/1e6-server.addr.srtt) //srtt = srtt + 0.125(rtt-srtt)
	//计算一个新的窗口值，由于rtt不是实时获取，不能做那种实时的变动的rtt窗口
	server.addr.windows_update_size = server.addr.bandwidth / 1000 * uint64(server.addr.srtt)
	if server.addr.windows_update_size < 163840 {
		server.addr.windows_update_size = 163840
	}
}

func (server *ServerConn) reg() error {

	var err error
	server.fd_m.Range(func(k, v interface{}) bool { //强制关闭现有客户端连接
		v.(*Conn).c.Close()
		server.fd_m.Delete(k)
		return true

	})
	server.conn, err = net.Dial("tcp", server.addr.addr)
	if err != nil {

		return err

	}
	server.inboundBuffer.Reset()
	n, err := server.conn.Read(server.inboundBuffer.Make(1024))
	if err != nil {
		//libraries.DEBUG("这里", err)
		return err
	}
	if n < 4 {
		return errors.New("msg too short")
	}
	server.inboundBuffer.Truncate(n)
	b := server.inboundBuffer.Next(4)
	if b[3] != 0 {
		return protocolErr
	}
	msglen := int(b[0]) | int(b[1])<<8 | int(b[2])<<16
	for olen := server.inboundBuffer.Len(); olen < msglen; olen = server.inboundBuffer.Len() {
		n, err := server.conn.Read(server.inboundBuffer.Make(msglen))
		if err != nil {
			//libraries.DEBUG("这里")
			return err
		}
		server.inboundBuffer.Truncate(olen + n)
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
				return err
			}
			server.tlsconn.RawWrite(server.buf[:n])
		}

		if err := server.tlsconn.Handshake(); err != nil {
			return err
		}
	}

	b = make([]byte, maxPlaintext)
	b[0] = cmd_reg
	server.tlsconn.Write(b)
	server.conn.Write(server.outboundBuffer.Bytes())
	server.outboundBuffer.Reset()
	b[0] = 0
	for i := 0; i < 7; i++ {
		server.tlsconn.Write(b)
		server.conn.Write(server.outboundBuffer.Bytes())
		server.outboundBuffer.Reset()
	}
	server.status = statusON
	server.c <- 0
	fmt.Printf("connect to %s success\r\n", server.addr.addr)
	return nil
}

func handleOut(server *ServerConn) {
	bufnum := runtime.NumCPU() * 4
	server.outChan = make(chan *tls.MsgBuffer, bufnum)
	server.outbufchan = make(chan *tls.MsgBuffer, bufnum)
	for i := 0; i < bufnum; i++ {
		server.outbufchan <- &tls.MsgBuffer{}
	}
	server.wait = make(chan int, 1)
	server.c = make(chan int)
	server.wait <- 0
	/*for i := len(server.outbufchan); i < cap(server.outbufchan); i++ {
		server.outbufchan <- &tls.MsgBuffer{}
	}*/

	go func() {
		for {
			select {
			case b := <-server.outChan:
				server.wait <- 0
				server.tlsconn.Write(b.Bytes())
				b.Reset()
				server.outbufchan <- b
				for i := 0; i < len(server.outChan); i++ {
					b := <-server.outChan
					server.tlsconn.Write(b.Bytes())
					b.Reset()
					server.outbufchan <- b
				}
				server.conn.Write(server.outboundBuffer.Bytes())
				server.outboundBuffer.Reset()
				<-server.wait
			case <-server.wait:
				<-server.c
			}
		}
	}()
}
func ping(server *ServerConn) {
	server.wait = make(chan int, 1)
	server.c = make(chan int)
	server.wait <- 0
	b := make([]byte, 9)
	b[0] = cmd_ping
	for {
		select {
		case <-time.After(time.Second):
			server.wait <- 0
			now := time.Now()
			if server.pingtime > server.pongtime {
				server.getRtt(now.UnixNano() - server.pingtime)
			}
			server.pingtime = now.UnixNano()
			pingtime := uint64(server.pingtime)

			b[1] = byte(pingtime & 255)
			b[2] = byte(pingtime >> 8 & 255)
			b[3] = byte(pingtime >> 16 & 255)
			b[4] = byte(pingtime >> 24 & 255)
			b[5] = byte(pingtime >> 32 & 255)
			b[6] = byte(pingtime >> 40 & 255)
			b[7] = byte(pingtime >> 48 & 255)
			b[8] = byte(pingtime >> 54 & 255)
			server.tlsconn.Write(b)

			server.conn.Write(server.outboundBuffer.Bytes())
			server.outboundBuffer.Reset()
			<-server.wait
		case <-server.wait:
			<-server.c
		}
	}

}
func (conn *Conn) Remoteclose() {
	if conn.server.tlsconn == nil || !conn.server.tlsconn.HandshakeComplete() {
		return
	}
	b := <-conn.server.outbufchan
	buf := b.Make(3)
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
		Certificates: []tls.Certificate{cert},
		ServerName:   "yy",
		RootCAs:      certPool,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
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
	if server.tlsconn != nil {
		server.conn.Write(server.outboundBuffer.Bytes())
		server.outboundBuffer.Reset()
	} else {
		server.conn.Write(b)
	}

	return len(b), nil
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
