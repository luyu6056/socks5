package main

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	_ "net/http/pprof"
	"server/codec"
	"server/config"
	"sort"
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
var (
	padding    = make([]byte, 15)
	client_m   sync.Map
	clientLock sync.Mutex
)

type f翻墙 struct {
	*gnet.EventServer
	addr      string
	pool      *ants.Pool
	mysqladdr string
	server    sync.Map
}
type mainServer struct {
	*gnet.EventServer
	addr string
	pool *ants.Pool
}
type client struct {
	fd_m   sync.Map
	key    string
	conn_m map[string]gnet.Conn
}

var gopool, _ = ants.NewPool(1024, ants.WithPreAlloc(true))

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
func main() {
	f := &f翻墙{addr: config.Server.Listen, pool: gopool}
	http.HandleFunc("/fd", func(w http.ResponseWriter, r *http.Request) {
		str := []string{}
		client_m.Range(func(k, c interface{}) bool {
			str = append(str, "server:"+k.(string))
			var s fdsort
			c.(*client).fd_m.Range(func(k, v interface{}) bool {
				s = append(s, v.(*Conn))
				return true
			})
			sort.Sort(s)
			for _, conn := range s {
				if conn.close == 0 {
					str = append(str, "fd"+fmt.Sprint(uint16(conn.fd[0])+uint16(conn.fd[1])<<8)+" "+strconv.Itoa(int(conn.windows_size)))
				} else {
					str = append(str, "fd"+fmt.Sprint(uint16(conn.fd[0])+uint16(conn.fd[1])<<8)+" "+conn.close_reason)
				}

			}

			return true
		})

		w.Write([]byte(strings.Join(str, "\r\n")))
	})
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

	defer f.pool.Release()

	codec := &CodecMysql{
		server: f,
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

	gnet.Serve(f, f.addr, gnet.WithLoopNum(3), gnet.WithReusePort(false), gnet.WithTCPKeepAlive(time.Second*600), gnet.WithCodec(codec), gnet.WithOutbuf(32), gnet.WithMultiOut(false), gnet.WithTicker(true))
}

type Conn struct {
	windows_size int64
	ctx          *Ctx
	conn         net.Conn
	close        int32
	address      string
	fd           [2]byte
	write        chan *tls.MsgBuffer
	recno        uint32
	msgno        uint32
	wait         chan bool
	send         uint64
	close_reason string
}

type Ctx struct {
	gnetconn gnet.Conn
	client   *client
	server   *f翻墙
}

func (hs *f翻墙) Tick() (delay time.Duration, action gnet.Action) {
	clientLock.Lock()
	client_m.Range(func(k, c interface{}) bool {
		if len(c.(*client).conn_m) == 0 {
			client_m.Delete(k)
		}
		return true
	})
	clientLock.Unlock()
	return time.Minute, gnet.None
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
		} else {
			hs.server.Store(c.RemoteAddr().String(), c.Context())
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
		if ctx.client != nil {
			ctx.client.fd_m.Range(func(k, v interface{}) bool {
				v.(*Conn).Close("客户端关闭链接")
				return true
			})
			key := c.LocalAddr().String()
			time.AfterFunc(time.Minute, func() {
				clientLock.Lock()
				if c1 := ctx.client.conn_m[key]; c1 == c {
					delete(ctx.client.conn_m, key)
				}

				clientLock.Unlock()
			})
		}

		c.SetContext(nil)
		hs.server.Delete(c.RemoteAddr().String())
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
		if ctx.client == nil {
			return
		}
		port := binary.BigEndian.Uint16(data[len(data)-2:])
		addr := string(data[headlen:len(data)-2]) + ":" + strconv.Itoa(int(port))

		conn := &Conn{}
		conn.ctx = ctx
		conn.address = addr
		conn.fd[0] = data[1]
		conn.fd[1] = data[2]

		conn.write = make(chan *tls.MsgBuffer, 64)

		conn.conn = nil
		conn.close = 0
		conn.recno = 0
		conn.msgno = 0
		conn.windows_size = 0
		conn.wait = make(chan bool)

		ctx.client.fd_m.Store(conn.fd, conn)
		antspool.Submit(func() {

			/*lAddr, err := net.ResolveTCPAddr("tcp", "202.81.235.114:0")
			if err != nil {
				conn.Close("fd拨号失败")
				conn.write = make(chan *tls.MsgBuffer, 1000000)
				return
			}

			fmt.Println(addr)//被请求的地址
			rAddr, err := net.ResolveTCPAddr("tcp", addr)
			if err != nil {
				conn.Close("fd拨号失败")
				conn.write = make(chan *tls.MsgBuffer, 1000000)
				return
			}
			netconn, err := net.DialTCP("tcp", lAddr, rAddr)*/
			netconn, err := net.Dial("tcp", addr)
			if err != nil {
				conn.Close("fd拨号失败")
				conn.write = make(chan *tls.MsgBuffer, 1000000)
				return
			} else {
				if conn.close == 0 {
					conn.conn = netconn
					handsocks.Invoke(conn)

					for b := range conn.write {
						if b == nil {
							conn.write = make(chan *tls.MsgBuffer, 1000000)
							return
						}
						conn.conn.Write(b.Bytes())
						buf_pool.Put(b)
					}

				}

			}

		})
	case cmd_msg:
		if ctx.client == nil {
			return
		}
		v, ok := ctx.client.fd_m.Load([2]byte{data[1], data[2]})
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

		if windows_update_size != 0 {

			old := atomic.AddInt64(&conn.windows_size, windows_update_size) - windows_update_size
			if old < 0 {
				antspool.Submit(func() {
					select {
					case conn.wait <- true:
					case <-time.After(time.Second):
					}
				})
			}
		}
		b := buf_pool.Get().(*tls.MsgBuffer)
		b.Reset()
		b.Write(data[headlen+8:])
		conn.write <- b

	case cmd_deletefd:
		if ctx.client == nil {
			return
		}
		v, ok := ctx.client.fd_m.Load([2]byte{data[1], data[2]})
		if ok {
			v.(*Conn).Close("客户端要求关闭")

		}
	case cmd_windowsupdate:
		if ctx.client == nil {
			return
		}
		v, ok := ctx.client.fd_m.Load([2]byte{data[1], data[2]})
		if ok {
			conn := v.(*Conn)
			windows_update_size := int64(data[3]) | int64(data[4])<<8 | int64(data[5])<<16 | int64(data[6])<<24 | int64(data[7])<<32 | int64(data[8])<<40 | int64(data[9])<<48 | int64(data[10])<<54
			if windows_update_size > 0 {
				old := atomic.AddInt64(&conn.windows_size, windows_update_size) - windows_update_size
				if old < 0 {
					antspool.Submit(func() {
						select {
						case conn.wait <- true:
						case <-time.After(time.Second):
						}
					})
				}
			}

		} else {
			b := make([]byte, 3)
			b[0] = cmd_deletefd
			b[1] = data[1]
			b[2] = data[2]
			c.AsyncWrite(b)
			return
		}
	case cmd_reg:
		clientLock.Lock()
		defer clientLock.Unlock()
		key := string(data[1:])
		C := &client{key: key}
		if v, ok := client_m.Load(key); ok {
			ctx.client = v.(*client)
			c.AsyncWrite(make([]byte, 65535*2)) //消灭分包
		} else {
			client_m.Store(key, C)
			ctx.client = C
			data[0] = cmd_deleteIp
			c.AsyncWrite(data)                  //清空客户端的fd
			c.AsyncWrite(make([]byte, 65535*2)) //消灭分包
		}

		if ctx.client.conn_m == nil {
			ctx.client.conn_m = make(map[string]gnet.Conn)
		}
		ctx.client.conn_m[c.LocalAddr().String()] = c

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
		conn.ctx.server.pool.Submit(func() {
			if conn.conn != nil {
				conn.conn.Close()
			}
			//fmt.Println(conn.fd, reason)
			conn.ctx.client.fd_m.Delete(conn.fd)
			conn.close_reason = reason
			b := buf_pool.Get().(*tls.MsgBuffer)
			b.Reset()
			buf := b.Make(3)
			buf[0] = cmd_deletefd
			buf[1] = conn.fd[0]
			buf[2] = conn.fd[1]
			conn.ctx.gnetconn.AsyncWrite(buf)
			buf_pool.Put(b)

			select {
			case conn.wait <- false:
			case <-time.After(time.Second * 10):
			}
			conn.write <- nil
		})
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
	var err error
	var n int
	defer func() {
		if err != nil {
			conn.Close(conn.address + " 网站读取出错" + err.Error())
		} else {
			conn.Close(conn.address + " read异常关闭")
		}

	}()

	buf := make([]byte, maxPlaintext)
	buf[0] = cmd_msg //数据包
	buf[1] = conn.fd[0]
	buf[2] = conn.fd[1]

	for conn.close == 0 {
		n, err = conn.conn.Read(buf[headlen:])
		if err != nil || n < 1 {
			if atomic.LoadInt32(&conn.close) == 0 {
				if e := err.Error(); !strings.Contains(e, ": i/o timeout") {

					return
				}
				continue
			} else {
				return
			}
		}

		msglen := headlen + n

		conn.ctx.gnetconn.AsyncWrite(buf[:msglen])
		atomic.AddInt64(&conn.windows_size, -1*int64(n))

		for atomic.LoadInt64(&conn.windows_size) <= 0 && conn.close == 0 {

			select {
			case flag := <-conn.wait:
				if !flag {
					return
				}
			case <-time.After(time.Second):
			}
		}
	}

})

type CodecMysql struct {
	mysqladdr string
	tlsconfig *tls.Config
	server    *f翻墙
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
				//fd_m:     new(sync.Map),
				gnetconn: c,
				server:   code.server,
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
