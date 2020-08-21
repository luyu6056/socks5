package main

import (
	"crypto/x509"
	"encoding/binary"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	_ "net/http/pprof"
	"server/codec"
	"server/config"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luyu6056/gnet"
	"github.com/luyu6056/tls"
	"github.com/panjf2000/ants/v2"
)

const (
	maxCiphertext            = 16384 + 2048
	maxPlaintext             = 16384
	framelimit               = 10240 //单个tcp包限制+2个len
	headlen                  = 3     //1cmd2fd
	outdelay                 = time.Millisecond
	CLIENT_SSL               = 0x00000800
	CLIENT_PROTOCOL_41       = 0x00000200
	CLIENT_SECURE_CONNECTION = 0x00008000 //1
	initWindowsSize          = 16384 * 40 //引入http2流控概念
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

var (
	padding = make([]byte, 15)
)

type f翻墙 struct {
	*gnet.EventServer
	addr      string
	pool      *ants.Pool
	mysqladdr string
}
type mainServer struct {
	*gnet.EventServer
	addr string
	pool *ants.Pool
}

var gopool, _ = ants.NewPool(1024, ants.WithPreAlloc(true))

func main() {
	go func() {
		err := http.ListenAndServe("0.0.0.0:8081", nil)
		if err != nil {
			http.ListenAndServe("0.0.0.0:8082", nil)
		}

	}()
	cert, err := tls.LoadX509KeyPair(config.Server.Mysql_ssl_cert, config.Server.Mysql_ssl_key)
	if err != nil {
		log.Fatalf("tls.LoadX509KeyPair err: %v", err)
	}
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile(config.Server.Mysql_ssl_ca)
	if err != nil {
		log.Fatalf("ioutil.ReadFile err: %v", err)
	}

	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		log.Fatalf("certPool.AppendCertsFromPEM err")
	}
	go func() {
		codec := &codec.Tlscodec{}
		h := &mainServer{addr: "tcp://:808", pool: gopool}
		go gnet.Serve(h, h.addr, gnet.WithLoopNum(4), gnet.WithReusePort(false), gnet.WithTCPKeepAlive(time.Second*600), gnet.WithCodec(codec), gnet.WithOutbuf(32), gnet.WithMultiOut(false))
		return
		h443 := &mainServer{addr: "tcp://:443", pool: gopool}
		gnet.Serve(h443, h443.addr, gnet.WithLoopNum(4), gnet.WithReusePort(true), gnet.WithTCPKeepAlive(time.Second*600), gnet.WithCodec(codec), gnet.WithOutbuf(64), gnet.WithMultiOut(false), gnet.WithTls(&tls.Config{
			Certificates:             []tls.Certificate{cert},
			RootCAs:                  certPool,
			NextProtos:               []string{"h2", "http/1.1"},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
			MinVersion: tls.VersionTLS12,
		}))
	}()
	f := &f翻墙{addr: config.Server.Listen, pool: gopool}
	defer f.pool.Release()

	codec := &CodecMysql{
		tlsconfig: &tls.Config{
			Certificates:             []tls.Certificate{cert},
			ClientAuth:               tls.RequireAndVerifyClientCert,
			ClientCAs:                certPool,
			PreferServerCipherSuites: false,
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Fatal(gnet.Serve(f, f.addr, gnet.WithLoopNum(8), gnet.WithReusePort(false), gnet.WithTCPKeepAlive(time.Second*600), gnet.WithCodec(codec), gnet.WithOutbuf(128), gnet.WithMultiOut(false)))
}

type Conn struct {
	ctx          *Ctx
	conn         net.Conn
	close        int32
	address      string
	fd           [2]byte
	write        chan *tls.MsgBuffer
	recno        uint32
	msgno        uint32
	windows_size int64
	wait         chan bool
	waittime     time.Time
	send         uint64
	closechan    chan *tls.MsgBuffer
}

type Ctx struct {
	gnetconn gnet.Conn
	fd_m     *sync.Map
}

func (hs *f翻墙) OnInitComplete(srv gnet.Server) (action gnet.Action) {
	log.Printf("http server started on %s (loops: %d)", hs.addr, srv.NumEventLoop)
	return
}

var connection_id uint32 = 100                                                                   //伪造的初始线程id
var capability_reserved = []byte{254, 255, 45, 2, 0, 255, 193, 21, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0} //伪造的flag值一直到reserved
func (hs *f翻墙) OnOpened(c gnet.Conn) (out []byte, action gnet.Action) {
	//fmt.Println(c.RemoteAddr().String())

	//10秒无响应或者响应错误
	time.AfterFunc(time.Second*10, func() {
		if c.Context() == nil && c != nil {
			c.Close()
		}
	})
	mysqlbuf := buf_pool.Get().(*tls.MsgBuffer)
	/*if len(hs.mysqladdr) > 5 {
		if strings.Contains(hs.mysqladdr, "unix") {
			//unix:/var/run/mysqld/mysqld.sock
			addr, err := net.ResolveUnixAddr("unix", hs.mysqladdr[5:])
			if err != nil {
				return
			}
			ctx.mysqlconn, err = net.DialUnix("unix", nil, addr)
			if err != nil {
				return
			}
		} else {
			//tcp://127.0.0.1:3306
			tcpAddr, err := net.ResolveTCPAddr("tcp4", hs.mysqladdr[6:])
			if err != nil {
				return
			}
			ctx.mysqlconn, err = net.DialTCP("tcp", nil, tcpAddr)
			if err != nil {
				return
			}
		}
	}

	if ctx.mysqlconn != nil {
		err := ctx.getMysqlHandshakePacket()
		if err != nil {
			ctx.mysqlconn = nil
		}
	}
	if ctx.mysqlconn == nil {*/
	//伪造握手包
	mysqlbuf.Reset()
	mysqlbuf.Make(4) //生成4位头
	mysqlbuf.WriteByte(10)
	mysqlbuf.WriteString("5.5.5-10.5.1-MariaDB")
	mysqlbuf.WriteByte(0)
	id := atomic.AddUint32(&connection_id, uint32(rand.Intn(5)))
	binary.LittleEndian.PutUint32(mysqlbuf.Make(4), uint32(id))
	b := mysqlbuf.Make(9)
	binary.LittleEndian.PutUint64(b, uint64(rand.Int63())) //产生个随机数，用于校验//auth-plugin-data-part-1
	b[8] = 0                                               //[00] filler
	mysqlbuf.Write(capability_reserved)                    //
	b = mysqlbuf.Make(13)
	binary.LittleEndian.PutUint64(b, uint64(rand.Int63()))     //挑战随机数的9-16位
	binary.LittleEndian.PutUint32(b[8:], uint32(rand.Int31())) //挑战随机数的16-20位
	b[12] = 0
	mysqlbuf.WriteString("mysql_native_password")                                 //密码套件
	mysqlbuf.WriteByte(0)                                                         //结束
	binary.LittleEndian.PutUint32(mysqlbuf.Bytes()[:4], uint32(mysqlbuf.Len())-4) //写入长度

	//}
	c.AsyncWrite(mysqlbuf.Bytes())
	buf_pool.Put(mysqlbuf)
	return
}

func (hs *f翻墙) OnClosed(c gnet.Conn, err error) (action gnet.Action) {
	//fmt.Println(time.Now(), c.RemoteAddr().String(), err)
	if ctx, ok := c.Context().(*Ctx); ok {
		ctx.fd_m.Range(func(k, v interface{}) bool {
			v.(*Conn).Close("客户端关闭链接")
			return true
		})

		c.SetContext(nil)
	}
	return
}

func (hs *f翻墙) React(data []byte, c gnet.Conn) (action gnet.Action) {
	ctx, ok := c.Context().(*Ctx)
	if !ok {
		return gnet.Close
	}
	switch data[0] {
	case cmd_getfd:

		port := binary.BigEndian.Uint16(data[len(data)-2:])
		addr := string(data[headlen:len(data)-2]) + ":" + strconv.Itoa(int(port))

		conn := &Conn{}
		conn.ctx = ctx
		conn.address = addr
		conn.fd[0] = data[1]
		conn.fd[1] = data[2]

		conn.write = make(chan *tls.MsgBuffer, 64)
		conn.closechan = make(chan *tls.MsgBuffer)
		conn.conn = nil
		conn.close = 0
		conn.recno = 0
		conn.msgno = 0
		conn.windows_size = initWindowsSize
		conn.wait = make(chan bool)

		ctx.fd_m.Store(conn.fd, conn)
		antspool.Submit(func() {
			netconn, err := net.Dial("tcp", addr)
			if err != nil {

				conn.Close("fd拨号失败")
				conn.closechan = make(chan *tls.MsgBuffer, 1000000)
				return
			} else {
				if conn.close == 0 {
					conn.conn = netconn
					handsocks.Invoke(conn)

					for b := range conn.write {

						conn.conn.Write(b.Bytes())
						buf_pool.Put(b)
					}

				}

			}

		})
	case cmd_msg:

		v, ok := ctx.fd_m.Load([2]byte{data[1], data[2]})
		if !ok {
			b := make([]byte, 3)
			b[0] = cmd_deletefd
			b[1] = data[1]
			b[2] = data[2]
			c.AsyncWrite(b)
			return
		}
		conn := v.(*Conn)
		windows_update_size := int64(data[3]) | int64(data[4])<<8 | int64(data[5])<<16 | int64(data[6])<<24 | int64(data[7])<<32 | int64(data[8])<<40 | int64(data[9])<<48 | int64(data[10])<<54
		if windows_update_size > 0 {
			old := atomic.AddInt64(&conn.windows_size, windows_update_size) - windows_update_size
			if old < 0 {
				antspool.Submit(func() {
					select {
					case conn.wait <- true:
					case <-time.After(time.Second * 2):
					}
				})
			}
		}
		b := buf_pool.Get().(*tls.MsgBuffer)
		b.Reset()
		b.Write(data[headlen+8:])
		select {
		case conn.write <- b:
		case conn.closechan <- b:
		}

	case cmd_deletefd:
		v, ok := ctx.fd_m.Load([2]byte{data[1], data[2]})
		if ok {
			v.(*Conn).Close("客户端要求关闭")

		}
	case cmd_windowsupdate:
		v, ok := ctx.fd_m.Load([2]byte{data[1], data[2]})
		if ok {
			conn := v.(*Conn)
			windows_update_size := int64(data[3]) | int64(data[4])<<8 | int64(data[5])<<16 | int64(data[6])<<24 | int64(data[7])<<32 | int64(data[8])<<40 | int64(data[9])<<48 | int64(data[10])<<54

			old := atomic.AddInt64(&conn.windows_size, windows_update_size) - windows_update_size
			if old < 0 {
				antspool.Submit(func() {
					select {
					case conn.wait <- true:
					case <-time.After(time.Second * 2):
					}
				})
			}
		}
	case cmd_reg:
		c.AsyncWrite(make([]byte, 65535*2)) //消灭分包
	case cmd_ping:
		data[0] = cmd_pong
		c.AsyncWrite(data)
	case cmd_none:
	default:
		action = gnet.Close
		return
	}

	return
}

func init() {
	/*if len(aesiv) < 16 {
		aesiv = append(aesiv, make([]byte, 16-len(aesiv))...)
	} else {
		aesiv = aesiv[:16]
	}
	if len(aeskey) < 16 {
		aeskey = append(aeskey, make([]byte, 16-len(aeskey))...)
	} else {
		aeskey = aeskey[:16]
	}*/
	rand.Seed(time.Now().UnixNano())
	//aesblock, _ = aes.NewCipher(aeskey)

}

var antspool, _ = ants.NewPool(10240)

func (conn *Conn) Close(reason string) {

	if atomic.CompareAndSwapInt32(&conn.close, 0, 1) {
		conn.ctx.fd_m.Delete(conn.fd)
		b := buf_pool.Get().(*tls.MsgBuffer)
		b.Reset()
		buf := b.Make(3)
		buf[0] = cmd_deletefd
		buf[1] = conn.fd[0]
		buf[2] = conn.fd[1]
		conn.ctx.gnetconn.AsyncWrite(buf)
		buf_pool.Put(b)
		if conn.conn != nil {
			conn.conn.Close()
		}
		select {
		case conn.wait <- true:
		default:
		}

	}

}

var buf_pool = &sync.Pool{
	New: func() interface{} {
		return &tls.MsgBuffer{}
	},
}

var handsocks, _ = ants.NewPoolWithFunc(65535, func(i interface{}) {
	conn, ok := i.(*Conn)
	if !ok {
		return
	}

	defer func() {

		close(conn.write)
	}()

	buf := make([]byte, maxPlaintext)
	buf[0] = cmd_msg //数据包
	buf[1] = conn.fd[0]
	buf[2] = conn.fd[1]
	for conn.close == 0 {
		n, err := conn.conn.Read(buf[headlen:])
		if err != nil {
			if atomic.LoadInt32(&conn.close) == 0 {
				conn.Close(conn.address + " 网站读取出错" + err.Error())
			}
			return
		}

		msglen := headlen + n

		conn.ctx.gnetconn.AsyncWrite(buf[:msglen])
		size := atomic.AddInt64(&conn.windows_size, -1*int64(n))
		if size <= 0 {
			conn.waittime = time.Now()
			select {
			case <-conn.wait:
			}
		}
	}

})

type CodecMysql struct {
	mysqladdr string
	tlsconfig *tls.Config
}

func (code *CodecMysql) Encode(c gnet.Conn, buf []byte) ([]byte, error) {
	return buf, nil
}

var bad_handshake = []byte{255, 19, 4, 66, 97, 100, 32, 104, 97, 110, 100, 115, 104, 97, 107, 101}

func (code *CodecMysql) Decode(c gnet.Conn) ([]byte, error) {

	if c.BufferLength() > 0 {
		data := c.Read()
		//处理ssl
		if _, ok := c.Context().(*Ctx); ok {
			//libraries.DEBUG(len(data))
			c.ResetBuffer()
			return data, nil
		} else if len(data) < 4 {
			return nil, nil
		}
		//检查mysql握手

		msglen := int(data[0]) | int(data[1])<<8 | int(data[2])<<16 + 4
		//消息长度不够
		if len(data) < msglen {
			return nil, nil
		}
		c.ShiftN(msglen)
		if data[3] != 1 {
			c.AsyncWrite([]byte{33, 0, 0, 2, 255, 132, 4, 35, 48, 56, 83, 48, 49, 71, 111, 116, 32, 112, 97, 99, 107, 101, 116, 115, 32, 111, 117, 116, 32, 111, 102, 32, 111, 114, 100, 101, 114})
			return nil, io.EOF
		}
		//读取flag

		flag := binary.LittleEndian.Uint32(data[4:8])
		if flag&CLIENT_SSL != 0 && msglen < 36 {
			c.AsyncWrite(bad_handshake)
			return nil, io.EOF
		}
		if flag&CLIENT_SSL != 0 {
			//设置tls
			c.UpgradeTls(code.tlsconfig)
			ctx := &Ctx{
				fd_m:     new(sync.Map),
				gnetconn: c,
			}
			c.SetContext(ctx)
			return nil, nil
		} else if msglen > 36 {
			mysqlbuf := buf_pool.Get().(*tls.MsgBuffer)
			mysqlbuf.Reset()
			mysqlbuf.Write(data[36:])
			username, _ := ReadNullTerminatedString(mysqlbuf)
			var password string
			if flag&CLIENT_SECURE_CONNECTION != 0 {
				password = string(mysqlbuf.Next(int(mysqlbuf.Next(1)[0])))
			} else {
				password, _ = ReadNullTerminatedString(mysqlbuf)
			}
			//构建errpaket
			mysqlbuf.Reset()
			b := mysqlbuf.Make(7)
			b[3] = 2
			b[4] = 0xff
			binary.LittleEndian.PutUint16(b[5:7], 1045)
			copy(b[7:13], []byte{35, 50, 56, 48, 48, 48})
			mysqlbuf.WriteString("Access denied for user '")
			mysqlbuf.WriteString(username)
			mysqlbuf.WriteString("'@'")
			addr := c.RemoteAddr().String()
			addr = addr[:strings.Index(addr, ":")]
			host, err := net.LookupAddr(addr)
			if err != nil && len(host) == 0 {
				mysqlbuf.WriteString(addr)
			} else {
				mysqlbuf.WriteString(host[0])
			}
			mysqlbuf.WriteString("' (using password: ")
			if password == "" {
				mysqlbuf.WriteString("NO))")
			} else {
				mysqlbuf.WriteString("YES))")
			}
			msglen = mysqlbuf.Len() - 4
			b = mysqlbuf.Bytes()[:3]
			b[0] = byte(msglen)
			b[1] = byte(msglen >> 8)
			b[2] = byte(msglen >> 16)
			c.AsyncWrite(mysqlbuf.Bytes())
			buf_pool.Put(mysqlbuf)
			return nil, nil
		}

	}
	return nil, nil

}
func ReadNullTerminatedString(msg *tls.MsgBuffer) (string, error) {
	var b []byte
	top := msg.Bytes()
	for k, v := range top {
		if v == 0 {
			b = make([]byte, k)
			copy(b, msg.Next(k+1))
			break
		}
	}
	return string(b), nil
}

func (hs *mainServer) OnInitComplete(srv gnet.Server) (action gnet.Action) {
	log.Printf("server started on %s (loops: %d)\r\n", hs.addr, srv.NumEventLoop)
	return
}

func (hs *mainServer) OnOpened(c gnet.Conn) (out []byte, action gnet.Action) {
	time.AfterFunc(time.Second*10, func() {
		if c.Context() == nil {
			c.Close()
		}
	})
	return
}

func (hs *mainServer) OnClosed(c gnet.Conn, err error) (action gnet.Action) {
	switch svr := c.Context().(type) {

	case *codec.Httpserver:
		svr.Request.Connection = ""

		codec.Httppool.Put(svr)

	case *codec.Http2server:
		hs.pool.Submit(func() {
			svr.Close()
		})
	}
	c.SetContext(nil)
	return
}

var hello = []byte("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello word!")

func (hs *mainServer) React(data []byte, c gnet.Conn) (action gnet.Action) {

	switch svr := c.Context().(type) {
	case *codec.Httpserver:
		switch svr.Request.Path {
		case "/hello":
			c.AsyncWrite(hello)
			return
		case "/getIP":
			buf := buf_pool.Get().(*tls.MsgBuffer)
			buf.Reset()
			buf.WriteString(`{"processedString":"` + c.RemoteAddr().String() + `"}`)
			svr.Output_data(buf.Bytes())
			buf_pool.Put(buf)
		case "/empty":
			svr.Output_data(nil)
		case "/garbage":
			svr.RandOut()
			return
		default:
			svr.Static()
		}
		if svr.Request.Connection == "close" {
			action = gnet.Close
		}

		return gnet.None

	case *codec.Http2server:
		svr.SendPool.Invoke(svr.WorkStream) //h2是异步，可能会Jitter抖动厉害
		return
	}
	return
}
