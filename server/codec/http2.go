package codec

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/url"
	"regexp"

	"github.com/klauspost/compress/gzip"
	"github.com/luyu6056/cache"
	"github.com/luyu6056/tls"

	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/luyu6056/gnet"
	"github.com/panjf2000/ants/v2"
	"golang.org/x/net/http2/hpack"
)

type Http2server struct {
	c        gnet.Conn
	InHeader http2FrameHeader
	Setting  struct {
		HEADER_TABLE_SIZE            int   //允许发送者以八位字节的形式通知远程端点用于解码头块的头压缩表的最大尺寸。编码器可以通过使用特定于头部块内头部压缩格式的信令来选择等于或小于此值的任何大小
		ENABLE_PUSH                  bool  //此设置可用于禁用服务器推送
		SETTINGS_INITIAL_WINDOW_SIZE int32 //初始化默认的窗口大小
		MAX_FRAME_SIZE               int   //指示发送者愿意接收的最大帧有效载荷的大小
		MAX_HEADER_LIST_SIZE         int   //此通报设置以八位字节的形式通知对等方发送方准备接受的标题列表的最大大小
	}
	WorkStream      *Http2stream
	ReadPool        *ants.Pool
	SendPool        *ants.Pool
	Streams         []*Http2stream
	ReadMetaHeaders *hpack.Decoder
	last_stream_id  uint32
	fps             uint32 //Frames Per Second,避免一些如CVE-2019-9512和CVE-2019-9515 ddos攻击，其实是限制客户端帧请求
	//IN_WINDOW_SIZE  int32 //接受到的窗口允许大小
	//OUT_WINDOW_SIZE int32 //发送出去的窗口允许大小
	//lock            sync.Mutex
	Conn   *ClientConn
	Origin string
}
type Http2stream struct {
	Out, Out2                       *tls.MsgBuffer
	Headers                         []hpack.HeaderField
	In                              *tls.MsgBuffer
	Id                              uint32
	IN_WINDOW_SIZE, OUT_WINDOW_SIZE int32
	sendch                          chan int8
	svr                             *Http2server
	close                           int8
	henc                            *hpack.Encoder
	headerbuf                       tls.MsgBuffer
	data                            *bytes.Reader
	compressbuf                     *tls.MsgBuffer
	query                           map[string][]string
	cookie                          map[string]string
	post                            map[string][]string
	session                         *cache.Hashvalue
	method, path, uri               string
	outCode                         int
	OutContentType                  string
	OutHeader                       map[string]string
	OutCookie                       map[string]httpcookie
	content_type                    string
	accept_encoding                 string
	referer                         string
}

const (
	http2streamflagadd = iota
	http2streamflagclose
)

var http2initconn_setting = http2writeSettings{
	{http2SettingMaxFrameSize, http2defaultMaxReadFrameSize},
	{http2SettingMaxConcurrentStreams, http2MaxConcurrentStreams},
	{http2SettingMaxHeaderListSize, http2initialHeaderTableSize},
	//{http2SettingInitialWindowSize, http2initialWindowSize},
}
var http2initconn_windows_update = http2writeWindow_Update{size: http2serverWindowSize, streamId: 0}

//初始化一个连接
func NewH2Conn(c gnet.Conn) *Http2server {
	h2s := Http2pool.Get().(*Http2server)
	h2s.Setting.HEADER_TABLE_SIZE = http2initialHeaderTableSize
	h2s.Setting.ENABLE_PUSH = true
	h2s.Setting.MAX_FRAME_SIZE = http2initialMaxFrameSize
	h2s.Setting.SETTINGS_INITIAL_WINDOW_SIZE = http2initialWindowSize
	h2s.Setting.MAX_HEADER_LIST_SIZE = 0
	h2s.Streams[0].OUT_WINDOW_SIZE = http2initialWindowSize
	h2s.Streams[0].IN_WINDOW_SIZE = http2serverWindowSize
	h2s.Streams[0].Out.Reset()
	h2s.SendPool.Tune(http2MaxConcurrentStreams)
	h2s.SendPool.Reboot()
	h2s.c = c
	h2s.Streams[0].svr = h2s
	h2s.last_stream_id = 0
	http2initconn_setting.writeFrame(h2s.Streams[0])
	http2initconn_windows_update.writeFrame(h2s.Streams[0])
	return h2s
}
func (h2s *Http2server) Close() {
	h2s.connError(http2ErrCodeNo)
	h2s.SendPool.Release()
	for h2s.SendPool.Running() > 0 {
		for _, stream := range h2s.Streams {
			if stream != nil {
				select {
				case stream.sendch <- http2streamflagclose:
				default:
				}
			}
		}
		time.Sleep(time.Second)
	}
	Http2pool.Put(h2s)
}

const (
	http2serverWindowSize       = (1 << 31) - 1 - http2initialWindowSize //服务器窗口
	http2fpslimit               = 999                                    //帧率限制，避免ddos攻击
	http2WindowsSizeWaitTimeout = time.Second * 10                       //当窗口值为负的时候，会chan等待新的窗口增加，异步运行的时候也许会出现updatewindows没发送chan，导致流的chan锁死，所以为负值时候update会强行发送chan，但是也怕强行发送chan卡死，所以加了个超时
	http2MaxConcurrentStreams   = 256
	http2headerlength           = 9
	// ClientPreface is the string that must be sent by new
	// connections from clients.
	http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	// SETTINGS_MAX_FRAME_SIZE default
	// http://http2.github.io/http2-spec/#rfc.section.6.5.2
	http2initialMaxFrameSize = 16384

	// NextProtoTLS is the NPN/ALPN protocol negotiated during
	// HTTP/2's TLS setup.
	http2NextProtoTLS = "h2"

	// http://http2.github.io/http2-spec/#SettingValues
	http2initialHeaderTableSize = 4096

	http2initialWindowSize = 65536 // 6.9.2 Initial Flow Control Window Size

	http2defaultMaxReadFrameSize = 1 << 20
)

type http2FrameHeader struct {
	//valid    bool // caller can access []byte fields in the Frame
	Type     uint8
	Flags    uint8
	Length   int
	StreamID uint32
}
type http2FrameType uint8

const (
	// Data Frame
	http2FlagDataEndStream = 0x1
	http2FlagDataPadded    = 0x8

	// Headers Frame
	http2FlagHeadersEndStream  = 0x1
	http2FlagHeadersEndHeaders = 0x4
	http2FlagHeadersPadded     = 0x8
	http2FlagHeadersPriority   = 0x20

	// Settings Frame
	http2FlagSettingsAck = 0x1

	// Ping Frame
	http2FlagPingAck = 0x1

	// Continuation Frame
	http2FlagContinuationEndHeaders = 0x4

	http2FlagPushPromiseEndHeaders = 0x4
	http2FlagPushPromisePadded     = 0x8
)
const (
	http2FrameData         = 0x0
	http2FrameHeaders      = 0x1
	http2FramePriority     = 0x2
	http2FrameRSTStream    = 0x3
	http2FrameSettings     = 0x4
	http2FramePushPromise  = 0x5
	http2FramePing         = 0x6
	http2FrameGoAway       = 0x7
	http2FrameWindowUpdate = 0x8
	http2FrameContinuation = 0x9
)

type http2ErrCode uint32

const (
	http2ErrCodeNo                 http2ErrCode = 0x0
	http2ErrCodeProtocol           http2ErrCode = 0x1
	http2ErrCodeInternal           http2ErrCode = 0x2
	http2ErrCodeFlowControl        http2ErrCode = 0x3
	http2ErrCodeSettingsTimeout    http2ErrCode = 0x4
	http2ErrCodeStreamClosed       http2ErrCode = 0x5
	http2ErrCodeFrameSize          http2ErrCode = 0x6
	http2ErrCodeRefusedStream      http2ErrCode = 0x7
	http2ErrCodeCancel             http2ErrCode = 0x8
	http2ErrCodeCompression        http2ErrCode = 0x9
	http2ErrCodeConnect            http2ErrCode = 0xa
	http2ErrCodeEnhanceYourCalm    http2ErrCode = 0xb
	http2ErrCodeInadequateSecurity http2ErrCode = 0xc
	http2ErrCodeHTTP11Required     http2ErrCode = 0xd
)

var http2errCodeName = map[http2ErrCode]string{
	http2ErrCodeNo:                 "NO_ERROR",
	http2ErrCodeProtocol:           "PROTOCOL_ERROR",
	http2ErrCodeInternal:           "INTERNAL_ERROR",
	http2ErrCodeFlowControl:        "FLOW_CONTROL_ERROR",
	http2ErrCodeSettingsTimeout:    "SETTINGS_TIMEOUT",
	http2ErrCodeStreamClosed:       "STREAM_CLOSED",
	http2ErrCodeFrameSize:          "FRAME_SIZE_ERROR",
	http2ErrCodeRefusedStream:      "REFUSED_STREAM",
	http2ErrCodeCancel:             "CANCEL",
	http2ErrCodeCompression:        "COMPRESSION_ERROR",
	http2ErrCodeConnect:            "CONNECT_ERROR",
	http2ErrCodeEnhanceYourCalm:    "ENHANCE_YOUR_CALM",
	http2ErrCodeInadequateSecurity: "INADEQUATE_SECURITY",
	http2ErrCodeHTTP11Required:     "HTTP_1_1_REQUIRED",
}

const (
	http2SettingHeaderTableSize      = 0x1
	http2SettingEnablePush           = 0x2
	http2SettingMaxConcurrentStreams = 0x3
	http2SettingInitialWindowSize    = 0x4
	http2SettingMaxFrameSize         = 0x5
	http2SettingMaxHeaderListSize    = 0x6
)

type http2ConnectionError http2ErrCode

func (e http2ConnectionError) Error() string {
	return fmt.Sprintf("connection error: %s", http2ErrCode(e))
}

var Http2pool = sync.Pool{New: func() interface{} {
	hs := &Http2server{}
	hs.ReadPool, _ = ants.NewPool(http2MaxConcurrentStreams)
	hs.SendPool, _ = ants.NewPool(http2MaxConcurrentStreams)
	hs.Streams = make([]*Http2stream, http2MaxConcurrentStreams)
	hs.Streams[0] = &Http2stream{sendch: make(chan int8), Out: &tls.MsgBuffer{}}
	hs.ReadMetaHeaders = hpack.NewDecoder(http2initialHeaderTableSize, nil)
	hs.Streams[0].svr = hs
	//hs.Request.Header = make(map[string]string)
	return hs
}}

//发送一个goaway顺便返回error
func (h2s *Http2server) connError(code http2ErrCode) error {

	stream := h2s.Streams[0]
	stream.Out.Reset()
	outbuf := stream.Out.Make(http2headerlength + 8)
	outbuf[0] = 0
	outbuf[1] = 0
	outbuf[2] = 4
	outbuf[3] = http2FrameGoAway
	outbuf[4] = 0
	outbuf[5] = 0
	outbuf[6] = 0
	outbuf[7] = 0
	outbuf[8] = 0
	outbuf[9] = byte(h2s.last_stream_id >> 24)
	outbuf[10] = byte(h2s.last_stream_id >> 16)
	outbuf[11] = byte(h2s.last_stream_id >> 8)
	outbuf[12] = byte(h2s.last_stream_id)
	outbuf[13] = byte(h2s.last_stream_id >> 24)
	outbuf[14] = byte(code >> 16)
	outbuf[15] = byte(code >> 8)
	outbuf[16] = byte(code)
	h2s.c.AsyncWrite(outbuf)
	return http2ConnectionError(code)
}

var stream_pool = sync.Pool{New: func() interface{} {
	hs := &Http2stream{Out: &tls.MsgBuffer{}, Out2: &tls.MsgBuffer{}, In: tls.NewBuffer(0)}
	hs.sendch = make(chan int8)
	hs.data = &bytes.Reader{}
	hs.compressbuf = &tls.MsgBuffer{}
	return hs
}}

type http2writeSettings [][2]int

func (settings http2writeSettings) writeFrame(stream *Http2stream) (err error) {
	msglen := len(settings) * 6
	outbuf := stream.Out.Make(msglen + http2headerlength)
	outbuf[0] = byte(msglen >> 16)
	outbuf[1] = byte(msglen >> 8)
	outbuf[2] = byte(msglen)
	outbuf[3] = http2FrameSettings
	outbuf[4] = 0
	outbuf[5] = 0
	outbuf[6] = 0
	outbuf[7] = 0
	outbuf[8] = 0
	var be = http2headerlength
	for _, setting := range settings {
		outbuf[be] = byte(setting[0] >> 8)
		outbuf[be+1] = byte(setting[0])
		outbuf[be+2] = byte(setting[1] >> 24)
		outbuf[be+3] = byte(setting[1] >> 16)
		outbuf[be+4] = byte(setting[1] >> 8)
		outbuf[be+5] = byte(setting[1])
		be += 6
	}

	return
}

type http2writeSettingsAck struct{}

func (settings http2writeSettingsAck) writeFrame(stream *Http2stream) (err error) {
	outbuf := stream.Out.Make(http2headerlength)
	outbuf[0] = 0
	outbuf[1] = 0
	outbuf[2] = 0
	outbuf[3] = http2FrameSettings
	outbuf[4] = http2FlagSettingsAck
	outbuf[5] = 0
	outbuf[6] = 0
	outbuf[7] = 0
	outbuf[8] = 0
	return
}

var (
	headerField_hsts                 = hpack.HeaderField{Name: "strict-transport-security", Value: "max-age= 31536000"}
	headerField_status200            = hpack.HeaderField{Name: ":status", Value: "200"}
	headerField_status206            = hpack.HeaderField{Name: ":status", Value: "206"}
	headerField_status404            = hpack.HeaderField{Name: ":status", Value: "404"}
	headerField_status302            = hpack.HeaderField{Name: ":status", Value: "302"}
	headerField_status500            = hpack.HeaderField{Name: ":status", Value: "500"}
	headerField_cachecontrol         = hpack.HeaderField{Name: "cache-control", Value: "max-age=86400"}
	headerField_nocache              = hpack.HeaderField{Name: "cache-control", Value: "no-store, no-cache, must-revalidate, max-age=0, s-maxage=0"}
	headerField_server               = hpack.HeaderField{Name: "server", Value: "gnet by luyu6056"}
	headerField_deflate              = hpack.HeaderField{Name: "content-encoding", Value: "deflate"}
	headerField_gzip                 = hpack.HeaderField{Name: "content-encoding", Value: "gzip"}
	headerField_status304            = hpack.HeaderField{Name: ":status", Value: "304"}
	headerField_firefox              = hpack.HeaderField{Name: "X-Firefox-Spdy", Value: "h2"}
	headerField_content_type_png     = hpack.HeaderField{Name: "content-type", Value: "image/png"}
	headerField_content_type_gif     = hpack.HeaderField{Name: "content-type", Value: "image/gif"}
	headerField_content_type_js      = hpack.HeaderField{Name: "content-type", Value: "application/javascript"}
	headerField_content_type_html    = hpack.HeaderField{Name: "content-type", Value: "text/html; charset=UTF-8"}
	headerField_content_type_css     = hpack.HeaderField{Name: "content-type", Value: "text/css"}
	headerField_content_type_default = hpack.HeaderField{Name: "content-type", Value: "application/octet-stream"}
	headerField_Accept_Ranges        = hpack.HeaderField{Name: "accept-ranges", Value: "bytes"}
	//headerField_allow_origin         = hpack.HeaderField{Name: "access-control-allow-origin", Value: config.Server.Origin}
)

type file_cache struct {
	deflatefile     []byte
	content_type    string
	content_type_h2 hpack.HeaderField
	etag            string
	modTime         int64
	file            []byte
	check           uint32 //1秒钟检查1次
	iscompress      bool
}

var h2_context_pool = sync.Pool{New: func() interface{} {
	return &Context{Buf: new(tls.MsgBuffer), In: new(tls.MsgBuffer), In2: new(tls.MsgBuffer)}
}}

func (stream *Http2stream) StaticHandler() (action gnet.Action) {
	var filename string
	etag := ""
	var range_start, range_end int
	for _, head := range stream.Headers {
		switch head.Name {
		case "if-match", "if-none-match":
			etag = head.Value
		case "range":
			if strings.Index(head.Value, "bytes=") == 0 {

				if e := strings.Index(head.Value, "-"); e > 6 {
					range_start, _ = strconv.Atoi(head.Value[6:e])
					range_end, _ = strconv.Atoi(head.Value[e+1:])
				}

			}
		case ":method":
			switch head.Value {
			case "OPTIONS":
				stream.henc.WriteField(headerField_status200)
				if stream.svr.Origin != "" {
					stream.henc.WriteField(hpack.HeaderField{Name: "access-control-allow-origin", Value: stream.svr.Origin})
				}

				stream.WriteData(nil, 0)
				return
			}
		}
	}
	var deflate, isgzip bool
	filename = stream.path
	deflate = strings.Contains(stream.accept_encoding, "deflate")
	if !deflate {
		isgzip = strings.Contains(stream.accept_encoding, "gzip")
	}
	if index := strings.IndexByte(filename, '?'); index > 0 {
		filename = filename[:index]
	}
	if filename == "/" {
		filename = "/index.html"
	}

	filename = static_patch + filename
	var f_cache *file_cache
	var f_cache_err error
	if cache, ok := static_cache.Load(filename); ok { //这个cache在http2那边
		f_cache = cache.(*file_cache)

		//有缓存，检查文件是否修改
		if !httpIswatcher && f_cache.etag != "" && atomic.CompareAndSwapUint32(&f_cache.check, 0, 1) {
			f_cache_err, f_cache = f_cache.Check(filename)
			time.AfterFunc(time.Second, func() { f_cache.check = 0 })
		}
	} else {
		if httpIswatcher {
			httpWatcher.Add(filename)
		}
		f_cache_err, f_cache = f_cache.Check(filename)

	}

	if f_cache_err == nil {
		if f_cache.etag == etag {
			stream.henc.WriteField(headerField_status304)
			stream.data.Reset(nil)
		} else if deflate && f_cache.iscompress { //deflate压缩资源
			stream.henc.WriteField(headerField_status200)
			stream.henc.WriteField(f_cache.content_type_h2)
			stream.henc.WriteField(headerField_deflate)
			stream.data.Reset(f_cache.deflatefile)
		} else if isgzip && f_cache.iscompress { //gzip可压缩资源
			stream.henc.WriteField(headerField_status200)
			stream.henc.WriteField(f_cache.content_type_h2)
			g := gzippool.Get().(*gzip.Writer)
			defer gzippool.Put(g)
			stream.compressbuf.Reset()
			g.Reset(stream.compressbuf)
			g.Write(f_cache.file)
			g.Flush()
			stream.henc.WriteField(headerField_gzip)
			stream.data.Reset(stream.compressbuf.Bytes())

		} else { //非压缩资源
			stream.henc.WriteField(headerField_status200)
			stream.henc.WriteField(f_cache.content_type_h2)
			stream.data.Reset(f_cache.file)
		}
		stream.henc.WriteField(hpack.HeaderField{Name: "etag", Value: f_cache.etag})
		stream.WriteData(stream.data, stream.data.Len())
		return

	} else {
		f, err := os.Open(filename)
		if err != nil {
			stream.Out404Frame(err)
			return
		}
		defer f.Close()
		fstat, err := f.Stat()
		if err != nil {
			stream.Out404Frame(err)
			return
		}
		f_cache.modTime = fstat.ModTime().Unix()
		if range_start > 0 || range_end > 0 {
			stream.henc.WriteField(headerField_status206)
			if range_end == 0 {
				range_end = int(fstat.Size())
			}
			f.Seek(int64(range_start), 0)
			stream.henc.WriteField(headerField_content_type_default)
			stream.henc.WriteField(headerField_Accept_Ranges)
			stream.henc.WriteField(hpack.HeaderField{Name: "content-range", Value: "bytes " + strconv.Itoa(range_start) + "-" + strconv.Itoa(range_end) + "/" + strconv.Itoa(int(fstat.Size()))})
			stream.WriteData(f, range_end-range_start)
		} else {
			stream.henc.WriteField(headerField_status200)
			stream.henc.WriteField(headerField_content_type_default)
			stream.WriteData(f, int(fstat.Size()))
		}

	}
	return
}

func (stream *Http2stream) WriteData(reader io.Reader, length int) {

	stream.henc.WriteField(headerField_server)
	stream.henc.WriteField(headerField_hsts)
	//stream.henc.WriteField(headerField_firefox)
	stream.writeFrame(reader, length)
	if stream.close == 3 {
		stream.svr.Streams[stream.Id] = nil
		stream_pool.Put(stream)
	}
}
func (stream *Http2stream) Out404Frame(err error) {
	stream.henc.WriteField(headerField_status404)
	stream.data.Reset(http404b)
	stream.henc.WriteField(headerField_server)
	stream.henc.WriteField(headerField_hsts)

	stream.writeFrame(stream.data, len(http404b))
	if stream.close == 3 {
		stream.svr.Streams[stream.Id] = nil
		stream_pool.Put(stream)
	}
}
func (stream *Http2stream) writeFrame(reader io.Reader, msglen int) (err error) {
	for k, v := range stream.OutHeader {
		stream.henc.WriteField(hpack.HeaderField{Name: k, Value: url.QueryEscape(v)})
	}
	stream.henc.WriteField(hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(msglen)})
	for name, v := range stream.OutCookie {
		cookie := url.QueryEscape(name) + "=" + url.QueryEscape(v.value)
		if v.max_age > 0 {
			cookie += "; Max-age=" + strconv.FormatUint(uint64(v.max_age), 10) + "; Path=/"
		}
		stream.henc.WriteField(hpack.HeaderField{Name: "set-cookie", Value: cookie})
	}

	makelen := stream.headerbuf.Len()
	stream.Out.Reset()
	buf := stream.Out.Make(http2headerlength + makelen)
	buf[0] = byte(makelen >> 16)
	buf[1] = byte(makelen >> 8)
	buf[2] = byte(makelen)
	buf[3] = http2FrameHeaders
	buf[4] = http2FlagHeadersEndHeaders
	buf[5] = byte(stream.Id >> 24)
	buf[6] = byte(stream.Id >> 16)
	buf[7] = byte(stream.Id >> 8)
	buf[8] = byte(stream.Id)
	copy(buf[http2headerlength:], stream.headerbuf.Bytes())
	if msglen == 0 || makelen >= stream.svr.Setting.MAX_FRAME_SIZE {

		buf[4] |= http2FlagHeadersEndStream
		stream.close |= 2
		stream.svr.c.AsyncWrite(buf)
		stream.Out.Reset()

	}


	for olen := stream.Out.Len(); msglen > 0; olen = stream.Out.Len() {
		makelen = stream.svr.Setting.MAX_FRAME_SIZE - olen
		outbuf := stream.Out.Make(http2headerlength + makelen)
		n, err := reader.Read(outbuf[http2headerlength:])

		if err != nil || n <= 0 {
			http2writeRST_STREAM(http2ErrCodeInternal).writeFrame(stream)
			return err
		}
		//总的流量窗口
		if atomic.LoadInt32(&stream.svr.Streams[0].OUT_WINDOW_SIZE) <= 0 {
			for atomic.LoadInt32(&stream.svr.Streams[0].OUT_WINDOW_SIZE) <= 0 {
				//fmt.Println(stream.Id,"卡住",stream.svr.Streams[0].OUT_WINDOW_SIZE)
				select {
				case flag := <-stream.svr.Streams[0].sendch: //等待放行
					if flag == http2streamflagclose {
						return err
					}
				case flag := <-stream.sendch: //通知关闭
					if flag == http2streamflagclose {
						return err
					}
				case <-time.After(time.Millisecond * 10):
				}
			}

			value := atomic.AddInt32(&stream.svr.Streams[0].OUT_WINDOW_SIZE, int32(-1*n))
			if value > 0 { // 尝试对其他阻塞的window解锁
				stream.svr.ReadPool.Submit(func() {
					select {
					case stream.svr.Streams[0].sendch <- http2streamflagadd:
					case <-time.After(time.Millisecond * 10):
					}
				})
			}

		} else {
			atomic.AddInt32(&stream.svr.Streams[0].OUT_WINDOW_SIZE, int32(-1*n))
		}
		if atomic.LoadInt32(&stream.OUT_WINDOW_SIZE) <= 0 {
			for atomic.LoadInt32(&stream.OUT_WINDOW_SIZE) <= 0 {
				select {
				case flag := <-stream.sendch: //等待放行
					if flag == http2streamflagclose {
						return err
					}
				case <-time.After(time.Millisecond * 10):
				}
			}
		} else {
			atomic.AddInt32(&stream.OUT_WINDOW_SIZE, int32(-1*n))
		}

		msglen -= n
		outbuf[0] = byte(n >> 16)
		outbuf[1] = byte(n >> 8)
		outbuf[2] = byte(n)
		outbuf[3] = http2FrameData
		outbuf[4] = 0
		outbuf[5] = byte(stream.Id >> 24)
		outbuf[6] = byte(stream.Id >> 16)
		outbuf[7] = byte(stream.Id >> 8)
		outbuf[8] = byte(stream.Id)

		if msglen == 0 {
			outbuf[4] = http2FlagDataEndStream
			stream.close |= 2
		}
		stream.svr.c.AsyncWrite(stream.Out.Next(olen + http2headerlength + n))
		stream.Out.Reset()

	}


	return nil
}

type http2writePing struct{}

func (http2writePing) writeFrame(stream *Http2stream) (err error) {
	outbuf := stream.Out.Make(http2headerlength + 8)
	outbuf[0] = 0
	outbuf[1] = 0
	outbuf[2] = 8
	outbuf[3] = http2FramePing
	outbuf[4] = http2FlagPingAck
	outbuf[5] = 0
	outbuf[6] = 0
	outbuf[7] = 0
	outbuf[8] = 0
	outbuf[9] = 0
	outbuf[10] = 0
	outbuf[11] = 0
	outbuf[12] = 0
	outbuf[13] = 0
	outbuf[14] = 0
	outbuf[15] = 0
	outbuf[16] = 0
	return nil
}

type http2writeWindow_Update struct {
	size     int32
	streamId uint32
}

func (svr http2writeWindow_Update) writeFrame(stream *Http2stream) (err error) {
	outbuf := stream.Out.Make(http2headerlength + 4)
	outbuf[0] = 0
	outbuf[1] = 0
	outbuf[2] = 4
	outbuf[3] = http2FrameWindowUpdate
	outbuf[4] = 0
	outbuf[5] = byte(svr.streamId >> 24)
	outbuf[6] = byte(svr.streamId >> 16)
	outbuf[7] = byte(svr.streamId >> 8)
	outbuf[8] = byte(svr.streamId)
	outbuf[9] = byte(svr.size >> 24)
	outbuf[10] = byte(svr.size >> 16)
	outbuf[11] = byte(svr.size >> 8)
	outbuf[12] = byte(svr.size)
	return nil
}

type http2writeRST_STREAM uint32

func (errcode http2writeRST_STREAM) writeFrame(stream *Http2stream) (err error) {
	stream.Out.Reset()
	outbuf := stream.Out.Make(http2headerlength + 4)
	outbuf[0] = 0
	outbuf[1] = 0
	outbuf[2] = 4
	outbuf[3] = http2FrameRSTStream
	outbuf[4] = 0
	outbuf[5] = byte(stream.Id >> 24)
	outbuf[6] = byte(stream.Id >> 16)
	outbuf[7] = byte(stream.Id >> 8)
	outbuf[8] = byte(stream.Id)
	outbuf[9] = byte(errcode >> 24)
	outbuf[10] = byte(errcode >> 16)
	outbuf[11] = byte(errcode >> 8)
	outbuf[12] = byte(errcode)
	stream.svr.c.AsyncWrite(outbuf)
	return nil
}

var (
	httpIswatcher bool
	httpWatcher   *fsnotify.Watcher
	static_cache  sync.Map
	static_patch  string
)

func init() {
	dir, _ := os.Getwd()
	static_patch = strings.ReplaceAll(dir, `\`, "/") + "/static"
	var err error
	httpWatcher, err = fsnotify.NewWatcher()
	httpIswatcher = err == nil
	go func() {
		for httpIswatcher {
			select {
			case event := <-httpWatcher.Events:

				filename := strings.ReplaceAll(event.Name, `\`, "/")
				cache, ok := static_cache.Load(filename)
				if ok {
					err, _ := cache.(*file_cache).Check(filename)
					if err == file_cache_err_NotFound {
						static_cache.Delete(filename)
					}
				}
			case err := <-httpWatcher.Errors:
				DebugLog("error:%v", err)
			}
		}
	}()
}

var (
	file_cache_err_NotFound  = errors.New("file not found")
	file_cache_file_TooLarge = errors.New("file too large")
)

const file_cache_limit = 1024 * 1024 * 5 //暂定5Mb是大文件
func (cache *file_cache) Check(filename string) (error, *file_cache) {
	f_cache := new(file_cache)
	f, err := os.OpenFile(filename, os.O_RDONLY, 0555)
	if err != nil {
		return file_cache_err_NotFound, cache
	}
	defer f.Close()
	fstat, err := f.Stat()
	if err != nil {
		return err, cache
	}
	if t := fstat.ModTime().Unix(); cache != nil && t == cache.modTime {
		return nil, cache
	} else {
		f_cache.modTime = t
	}
	if fstat.Size() == 0 {
		return nil, cache
	} else if fstat.Size() > file_cache_limit {
		return file_cache_file_TooLarge, cache
	}
	f_cache.file = make([]byte, fstat.Size())
	_, err = io.ReadFull(f, f_cache.file)
	if err != nil {
		return err, cache
	}
	f_cache.etag = strconv.Itoa(int(crc32.ChecksumIEEE(f_cache.file)))
	f_cache.iscompress = true
	s := strings.Split(filename, ".")
	name := s[len(s)-1]
	switch {
	case strings.Contains(name, "css"):
		f_cache.content_type_h2 = headerField_content_type_css
		f_cache.content_type = "text/css"
	case strings.Contains(name, "html"):
		f_cache.content_type_h2 = headerField_content_type_html
		f_cache.content_type = "text/html;charset=utf-8"
	case strings.Contains(name, "js"):
		f_cache.content_type_h2 = headerField_content_type_js
		f_cache.content_type = "application/javascript"
	case strings.Contains(name, "gif"):
		f_cache.iscompress = false
		f_cache.content_type_h2 = headerField_content_type_gif
		f_cache.content_type = "image/gif"
	case strings.Contains(name, "png"):
		f_cache.iscompress = false
		f_cache.content_type_h2 = headerField_content_type_png
		f_cache.content_type = "image/png"
	default:
		f_cache.iscompress = false
		f_cache.content_type_h2 = headerField_content_type_default
		f_cache.content_type = "application/octet-stream"
	}
	if f_cache.iscompress {
		buf := &tls.MsgBuffer{}
		buf.Reset()
		w := CompressNoContextTakeover(buf, 6)
		w.Write(f_cache.file)
		w.Close()
		f_cache.deflatefile = make([]byte, buf.Len())
		copy(f_cache.deflatefile, buf.Bytes())
	}
	static_cache.Store(filename, f_cache)
	return nil, f_cache
}
func (stream *Http2stream) AddQuery(key, value string) {
	stream.query[key] = append(stream.query[key], value)
}
func (stream *Http2stream) Body() []byte {
	return stream.In.Bytes()
}
func (stream *Http2stream) Close() {
	stream.svr.Close()
}
func (stream *Http2stream) Cookie(key string) string {

	return stream.cookie[key]
}
func (stream *Http2stream) DelSession() {
	if stream.session != nil {
		stream.session.Hdel()
	}
}
func (stream *Http2stream) GetAllPost() map[string][]string {
	return nil
}
func (stream *Http2stream) GetAllQuery() map[string][]string {
	return stream.query
}
func (stream *Http2stream) Header(name string) string {
	for _, head := range stream.Headers {
		if head.Name == name {
			return head.Value
		} else if head.Name == strings.ToLower(name) {
			return head.Value
		}

	}
	return ""
}
func (stream *Http2stream) IP() (ip string) {

	if ip = stream.Header("X-Real-IP"); ip == "" {
		ip = stream.svr.c.RemoteAddr().String()
	}
	re3, _ := regexp.Compile(`:\d+$`)
	ip = re3.ReplaceAllString(ip, "")
	return ip
}
func (stream *Http2stream) Method() string {
	return stream.method
}
func (stream *Http2stream) Path() string {
	return stream.path
}
func (stream *Http2stream) Post(key string) string {
	if len(stream.post[key]) > 0 {
		return stream.post[key][0]
	}
	return ""
}
func (stream *Http2stream) PostSlice(key string) []string {
	return stream.post[key]
}
func (stream *Http2stream) Query(key string) string {
	if len(stream.query[key]) > 0 {
		return stream.query[key][0]
	}
	return ""
}
func (stream *Http2stream) RangeDownload(b HttpIoReader, size int64, name string) {
	var range_start, range_end int
	for _, head := range stream.Headers {
		switch head.Name {
		case "range":
			if strings.Index(head.Value, "bytes=") == 0 {

				if e := strings.Index(head.Value, "-"); e > 6 {
					range_start, _ = strconv.Atoi(head.Value[6:e])
					range_end, _ = strconv.Atoi(head.Value[e+1:])
				}

			}
		}
	}
	if range_start > 0 || range_end > 0 {
		stream.henc.WriteField(headerField_status206)
		if range_end == 0 {
			range_end = int(size)
		}
		if _, e := b.Seek(int64(range_start), 0); e != nil {
			stream.OutErr(e)
			return
		}
		stream.henc.WriteField(headerField_Accept_Ranges)
		stream.henc.WriteField(hpack.HeaderField{Name: "content-range", Value: "bytes " + strconv.Itoa(range_start) + "-" + strconv.Itoa(range_end) + "/" + strconv.Itoa(int(size))})
		stream.henc.WriteField(hpack.HeaderField{Name: "content-disposition", Value: `attachment; filename*="utf8''` + url.QueryEscape(name) + `"`})
		stream.WriteData(b, range_end-range_start)

	} else {
		stream.henc.WriteField(headerField_status200)
		stream.henc.WriteField(headerField_content_type_default)
		stream.henc.WriteField(hpack.HeaderField{Name: "content-disposition", Value: `attachment; filename*="utf8''` + url.QueryEscape(name) + `"`})
		stream.WriteData(b, int(size))
	}

	return
}
func (stream *Http2stream) OutErr(err error) {
	if Errfunc != nil {
		if Errfunc(stream, err) {
			return
		}
	}
	buf := &tls.MsgBuffer{}
	buf.WriteString(err.Error())
	stream.henc.WriteField(headerField_status500)

	stream.writeFrame(buf, buf.Len())
}
func (stream *Http2stream) Redirect(url string) {

	stream.henc.WriteField(headerField_status302)
	stream.henc.WriteField(hpack.HeaderField{Name: "location", Value: url})
	stream.writeFrame(nil, 0)
}
func (stream *Http2stream) RemoteAddr() string {
	return stream.svr.c.RemoteAddr().String()
}
func (stream *Http2stream) Session() *cache.Hashvalue {
	if stream.session == nil {
		//检查sessionID
		var has bool
		sessionIdKey := stream.Cookie("sessionID")
		if sessionIdKey != "" {
			stream.session, has = cache.Has(sessionIdKey, "session")
		}
		//不存在则创建一个
		if !has {
			has = true
			//循环检查到一个没用过的sessionIdKey
			for has {
				b := make([]byte, 8)
				binary.LittleEndian.PutUint64(b, atomic.AddUint64(&sessionID, 1))
				sha := sha256.Sum256(Str2bytes(strconv.FormatInt(time.Now().UnixNano(), 10) + string(b)))
				sessionIdKey = strings.TrimRight(base64.URLEncoding.EncodeToString(sha[:]), "=")
				_, has = cache.Has(sessionIdKey, "session")
			}
			stream.SetCookie("sessionID", sessionIdKey, 7*86400)
			stream.session = cache.Hget(sessionIdKey, "session")
			stream.session.Set("sessionID", sessionIdKey)
			stream.session.Expire(8 * 3600) //给个临时session
		}
	}
	return stream.session
}
func (stream *Http2stream) SetCookie(name, value string, max_age uint32) {
	stream.OutCookie[name] = httpcookie{
		value:   value,
		max_age: max_age,
	}
}
func (stream *Http2stream) SetCode(code int) {
	stream.outCode = code
}
func (stream *Http2stream) SetContentType(t string) {
	stream.OutContentType = t
}
func (stream *Http2stream) SetHeader(key, value string) {
	stream.OutHeader[key] = value
}
func (stream *Http2stream) URI() string {
	return stream.uri
}
func (stream *Http2stream) Referer() string {
	return stream.referer
}
func (stream *Http2stream) Write(b []byte) {

	if stream.outCode != 0 && httpCode(stream.outCode).Bytes() != nil {
		stream.henc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(stream.outCode)})
	} else {
		stream.henc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	}
	stream.henc.WriteField(headerField_nocache)
	if stream.OutContentType != "" {
		stream.henc.WriteField(hpack.HeaderField{Name: "content-type", Value: stream.OutContentType})
	} else {
		stream.henc.WriteField(headerField_content_type_html)

	}
	stream.Out2.Reset()
	stream.Out2.Write(b)
	stream.writeFrame(stream.Out2, stream.Out2.Len())
}

func (stream *Http2stream) WriteString(str string) {
	stream.Write(Str2bytes(str))
}
