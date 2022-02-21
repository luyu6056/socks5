package codec

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"io"
	"io/ioutil"
	"math/rand"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/gzip"
	"github.com/luyu6056/cache"
	"github.com/luyu6056/gnet"
	"github.com/luyu6056/tls"
)

type Httpserver struct {
	session          *cache.Hashvalue
	workRequest      *Request
	c                gnet.Conn
	ishttps, isClose bool
	Origin           string
	Requests         []*Request
	//StartTime      time.Time
}

func NewHttpServer(c gnet.Conn, ishttps bool) (hs *Httpserver) {
	hs = &Httpserver{
		Requests: make([]*Request, 0),
		c:        c,
		ishttps:  ishttps,
	}
	hs.workRequest = NewRequest(hs)
	return
}
func (hs *Httpserver) GetWorkRequest() *Request {
	req := hs.workRequest
	hs.workRequest = NewRequest(hs)
	return req
}
func (hs *Httpserver) Wake() {
	if len(hs.Requests) > 1 && hs.Requests[0].dataSize > -1 {
		end := 0
		for req := hs.Requests[end]; req.dataSize > -1; req = hs.Requests[end] {
			req.Httpfinish()
			req.Recovery()
			end++
		}
		copy(hs.Requests, hs.Requests[end:])
		hs.Requests = hs.Requests[:len(hs.Requests)-end]
	}
}
func (hs *Httpserver) Close() {
	if !hs.isClose {
		//hs.close <- true
		hs.session = nil
		hs.c.Close()
		hs.isClose = true
	}

}

type httpcookie struct {
	value   string
	max_age uint32
}
type httpQuery struct {
	key   string
	value []string
}
type Request struct {
	hs               *Httpserver
	Code             int
	CodeMsg          string
	Proto, method    string
	path, query, uri string
	remoteAddr       string
	keep_alive       bool
	header           map[string]string
	cookie           map[string]string
	body             []byte
	queryS           []httpQuery
	postS            []httpQuery
	//输出相关
	connWrite      func([]byte) error
	outCode        int
	outContentType string
	outHeader      map[string]string
	outCookie      map[string]httpcookie
	//输出buffer相关
	data     io.ReadCloser  //消息主体
	dataSize int            //dataSize大于-1就输出，所以要放到最后赋值
	out      *tls.MsgBuffer //输出消息用buffer，包含header等信息
	out1     *tls.MsgBuffer
}

var requestPool = sync.Pool{New: func() interface{} {
	r := &Request{out: new(tls.MsgBuffer), out1: new(tls.MsgBuffer)}
	r.outHeader = make(map[string]string)
	r.outCookie = make(map[string]httpcookie)
	r.header = make(map[string]string)
	r.body = make([]byte, 0)
	r.dataSize = -1
	return r
}}

func NewRequest(hs *Httpserver) (req *Request) {
	req = requestPool.Get().(*Request)
	req.hs = hs
	req.connWrite = hs.c.WriteNoCodec
	req.hs.Requests = append(req.hs.Requests, req)
	return req
}
func (r *Request) Recovery() {
	for k := range r.outHeader {
		delete(r.outHeader, k)
	}
	for k := range r.outCookie {
		delete(r.outCookie, k)
	}
	for k := range r.header {
		delete(r.header, k)
	}
	for k := range r.cookie {
		delete(r.cookie, k)
	}
	r.cookie = nil
	r.queryS = r.queryS[:0]
	r.postS = r.postS[:0]
	r.outCode = 0
	r.outContentType = ""
	r.query = ""
	r.data = nil
	r.keep_alive = false
	r.dataSize = -1
	r.body = r.body[:0]
	requestPool.Put(r)
}

var gzippool = sync.Pool{New: func() interface{} {
	w, _ := gzip.NewWriterLevel(nil, 6)
	return w
}}

func (r *Request) Wake() {
	r.hs.c.Wake()
}
func (r *Request) GetHeader(key string) string {
	return r.header[key]
}

func (r *Request) WriteBuf(b *tls.MsgBuffer) {
	r.Write(b.Bytes())
}
func (r *Request) WriteString(str string) {
	r.Write(Str2bytes(str))
}
func (r *Request) Write(b []byte) {
	r.out.Reset()
	if r.outCode != 0 && httpCode(r.outCode).Bytes() != nil {
		r.out.Write(httpCode(r.outCode).Bytes())
	} else {
		r.out.Write(http1head200)
	}
	r.out.Write(http1nocache)
	if r.outContentType != "" {
		r.out.WriteString("Content-Type: ")
		r.out.WriteString(r.outContentType)
		r.out.WriteString("\r\n")
	} else {
		r.out.Write([]byte("Content-Type: text/html;charset=utf-8\r\n"))
	}
	r.out1.Reset()
	if len(b) > 9192 && strings.Contains(r.GetHeader("Accept-Encoding"), "deflate") {
		w := CompressNoContextTakeover(r.out1, 6)
		w.Write(b)
		w.Close()
		r.out.Write(http1deflate)
	} else {
		r.out1.Write(b)
	}
	r.data = r.out1
	r.dataSize = r.out1.Len()
}
func (r *Request) WriteNoCompress(b []byte) {
	r.out.Reset()
	r.out.Write(http1head200)
	r.out.Write([]byte("Content-Type: text/html;charset=utf-8\r\n"))
	r.out1.Reset()
	r.out1.Write(b)
	r.data = r.out1
	r.dataSize = r.out1.Len()
}
func (r *Request) RemoteAddr() string {
	return r.hs.c.RemoteAddr().String()
}
func (r *Request) IP() (ip string) {

	if ip = r.GetHeader("X-Real-IP"); ip == "" {
		ip = r.hs.c.RemoteAddr().String()
	}
	re3, _ := regexp.Compile(`:\d+$`)
	ip = re3.ReplaceAllString(ip, "")
	return ip
}

func (r *Request) UserAgent() string {
	return r.GetHeader("UserAgent")
}
func (r *Request) URI() string {
	if r.hs.ishttps {
		return fmt.Sprintf("https://%s%s", r.header["Host"], r.uri)
	}
	return fmt.Sprintf("http://%s%s", r.header["Host"], r.uri)
}
func (r *Request) Referer() string {
	return r.header["Referer"]
}

var errprotocol = errors.New("the client is not using the websocket protocol:")

//http升级为websocket
func (r *Request) Upgradews() (err error) {
	//
	r.out.Reset()
	/*if !(strings.Contains(c.Request.Head, "Connection: Upgrade")) {

		r.out.WriteString("HTTP/1.1 400 Error\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nConnection: close\r\n\r\nUnknonw MSG")
		DebugLog("ws协议没有upgrade")
		return errprotocol
	}*/
	if r.method != "GET" {

		r.out.WriteString("HTTP/1.1 403 Error\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nConnection: close\r\n\r\nUnknonw MSG")
		DebugLog("ws协议没有get")
		return errprotocol
	}
	/*DebugLog(c.Request.Head)
	if !(strings.Contains(c.Request.Head, "Sec-WebSocket-Extensions")) {

		r.out.WriteString("HTTP/1.1 400 Error\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nConnection: close\r\n\r\nUnknonw MSG")
		DebugLog("ws协议没有Extensions")
		return
	}*/

	if r.hs.Origin != "" && r.header["Origin"] != r.hs.Origin {
		r.out.WriteString("HTTP/1.1 403 Error\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nConnection: close\r\n\r\nUnknonw MSG")
		DebugLog("ws来自错误的Origin")
		return errprotocol
	}
	if r.header["Upgrade"] != "websocket" {
		r.out.WriteString("HTTP/1.1 403 Error\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nConnection: close\r\n\r\nUnknonw MSG")
		DebugLog("ws协议没有upgrade")
		return errprotocol
	}

	if r.header["Sec-WebSocket-Version"] != "13" {
		r.out.WriteString("HTTP/1.1 403 Error\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nConnection: close\r\n\r\nUnknonw MSG")
		DebugLog("ws协议没有Extensions")
		return errprotocol
	}

	var challengeKey string

	if challengeKey = r.header["Sec-WebSocket-Key"]; challengeKey == "" {
		r.WriteString("HTTP/1.1 403 Error\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nConnection: close\r\n\r\nUnknonw MSG")
		DebugLog("ws协议没有Extensions")
		return errprotocol
	}
	id := atomic.AddInt32(&ClientId, 1)
	ws := &WSconn{
		IsServer:   true,
		ReadFinal:  true,
		Http:       r.hs,
		Conn:       &ClientConn{BeginTime: time.Now().Unix(), IP: r.IP(), UserAgent: r.GetHeader("User-Agent"), Id: id},
		Write:      r.hs.c.WriteNoCodec,
		IsCompress: strings.Contains(r.header["Sec-WebSocket-Extensions"], "permessage-deflate"),
		readbuf:    &tls.MsgBuffer{},
	}
	ws.Conn.Output_data = ws.Output_data
	r.hs.c.SetContext(ws)
	r.out.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ")
	r.out.WriteString(ComputeAcceptKey(challengeKey))
	r.out.WriteString("\r\n")
	if ws.IsCompress {
		r.out.WriteString("Sec-Websocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n")
	}
	r.out.WriteString("\r\n")
	r.hs.c.WriteNoCodec(r.out.Bytes())

	return nil
}

func (req *Request) Parsereq(data []byte) (int, []byte, error) {
	sdata := string(data)
	var i, s int
	var line string
	var clen int
	var q = -1
	// method, path, proto line

	req.Proto = ""
	i = bytes.IndexByte(data, 32)
	if i == -1 {
		return 0, nil, nil
	}
	req.method = sdata[:i]
	l := len(sdata)
	for i, s = i+1, i+1; i < l; i++ {
		if data[i] == 63 && q == -1 {
			q = i
		} else if data[i] == 32 {
			if q != -1 {
				req.path = sdata[s:q]
				req.query = sdata[q+1 : i]
			} else {
				req.path = sdata[s:i]
			}
			req.uri = sdata[s:i]
			i++
			s = bytes.Index(data[i:], []byte{13, 10})
			if s > -1 {
				s += i
				req.Proto = sdata[i:s]
			}

			break
		}
	}
	switch req.Proto {
	case "HTTP/1.0":
		req.keep_alive = false
	case "HTTP/1.1":
		req.keep_alive = true
	default:
		return 0, nil, fmt.Errorf("malformed request")
	}
	req.body = req.body[:0]
	//fmt.Println(sdata)
	for s += 2; s < l; s += i + 2 {
		i = bytes.Index(data[s:], []byte{13, 10})
		if i == -1 {
			return 0, nil, nil
		}
		line = sdata[s : s+i]
		if i > 15 {
			switch {
			case line[:15] == "Content-Length:", line[:15] == "Content-length:":
				clen, _ = strconv.Atoi(line[16:])
			case line == "Connection: close", line == "Connection: Close":
				req.keep_alive = false
			default:
				j := bytes.IndexByte(data[s:s+i], 58)
				if j == -1 {
					return 0, nil, nil
				}
				req.header[line[:j]] = line[j+2:]
			}
		} else if i == 0 {
			s += i + 2
			if clen == 0 && req.header["Transfer-Encoding"] == "chunked" {
				req.body = req.body[:0]
				for ; s < l; s += 2 {
					i = bytes.Index(data[s:], []byte{13, 10})
					if i == -1 {
						return 0, nil, nil
					}
					b := make([]byte, 8)
					if i&1 == 0 {
						hex.Decode(b[8-i/2:], data[s:s+i])
					} else {
						tmp, _ := hex.DecodeString("0" + sdata[s:s+i])
						copy(b[7-i/2:], tmp)

					}
					clen = int(b[0])<<56 | int(b[1])<<48 | int(b[2])<<40 | int(b[3])<<32 | int(b[4])<<24 | int(b[5])<<16 | int(b[6])<<8 | int(b[7])
					s += i + 2
					if l-s < clen {
						return 0, nil, nil
					}
					if clen > 0 {
						req.body = append(req.body, data[s:s+clen]...)
						s += clen
					} else if l-s == 2 && data[s] == 13 && data[s+1] == 10 {
						req.decodeQueryPost()

						return s + 2, req.body, nil
					}

				}

			} else {
				if l-s < clen {
					return 0, nil, nil
				}
				req.body = append(req.body, data[s:s+clen]...)
				req.decodeQueryPost()

				return s + clen, req.body, nil
			}
		} else {
			j := bytes.IndexByte(data[s:s+i], 58)
			req.header[line[:j]] = line[j+2:]
		}

	}
	// not enough data
	return 0, nil, nil
}
func (req *Request) decodeQueryPost() {
	if req.query != "" {
		for _, str := range strings.Split(req.query, "&") {
			s := strings.Split(str, "=")
			if len(s) == 2 {
				k, err1 := url.QueryUnescape(s[0])
				v, err2 := url.QueryUnescape(s[1])
				if err1 == nil && err2 == nil {
					req.addquery(k, v)
				}
			}
		}
	}
	if req.method == "POST" {
		if strings.Contains(req.header["Content-Type"], "application/x-www-form-urlencoded") {
			for _, str := range strings.Split(string(req.body), "&") {
				if i := strings.Index(str, "="); i > 0 {
					k, err1 := url.QueryUnescape(str[:i])
					v, err2 := url.QueryUnescape(str[i+1:])
					if err1 == nil && err2 == nil {
						req.addpost(k, v)
					}

				}
			}
		}
		if strings.Contains(req.header["Content-Type"], "multipart/form-data") {
			if i := strings.Index(req.header["Content-Type"], "boundary="); i > -1 {
				for _, str := range strings.Split(string(req.body), "--"+req.header["Content-Type"][i+9:]+"\r\n") {
					i := strings.Index(str, "\r\n")

					if i > -1 {
						if strings.Contains(str[:i], "Content-Disposition: form-data;") {
							var key, value string
							if j := strings.Index(str[:i], `name="`); j > -1 {
								key, _ = url.QueryUnescape(str[j+6 : i-1])
							}
							if j := strings.Index(str[i+4:], "\r\n"); j > -1 {
								value, _ = url.QueryUnescape(str[i+4 : i+4+j])
							}
							if key != "" {
								req.addpost(key, value)
							}
						}

					}

				}
			}

		}
	}

}
func (req *Request) addquery(name, value string) {
	for k, v := range req.queryS {
		if v.key == name {
			req.queryS[k].value = append(req.queryS[k].value, value)
			return
		}
	}
	oldlen := len(req.queryS)
	if oldlen+1 > cap(req.queryS) {
		req.queryS = append(req.queryS, httpQuery{
			key:   name,
			value: []string{value},
		})
	} else {
		req.queryS = req.queryS[:oldlen+1]
		req.queryS[oldlen].key = name
		req.queryS[oldlen].value = req.queryS[oldlen].value[:0]
		req.queryS[oldlen].value = append(req.queryS[oldlen].value, value)
	}
}
func (req *Request) addpost(name, value string) {
	for k, v := range req.postS {
		if v.key == name {
			req.postS[k].value = append(req.postS[k].value, value)
			return
		}
	}
	oldlen := len(req.postS)
	if oldlen+1 > cap(req.postS) {
		req.postS = append(req.postS, httpQuery{
			key:   name,
			value: []string{value},
		})
	} else {
		req.postS = req.postS[:oldlen+1]
		req.postS[oldlen].key = name
		req.postS[oldlen].value = req.postS[oldlen].value[:0]
		req.postS[oldlen].value = append(req.postS[oldlen].value, value)

	}
}

var (

	//http1origin  = []byte("Access-Control-Allow-Origin: " + config.Server.Origin + "\r\n")
	http1head200 = []byte("HTTP/1.1 200 OK\r\nserver: gnet by luyu6056\r\n")
	http1head206 = []byte("HTTP/1.1 206 Partial Content\r\nserver: gnet by luyu6056\r\n")
	http1head304 = []byte("HTTP/1.1 304 Not Modified\r\nserver: gnet by luyu6056\r\n")
	http1deflate = []byte("Content-encoding: deflate\r\n")
	http1gzip    = []byte("Content-encoding: gzip\r\n")
	http404b, _  = ioutil.ReadFile(static_patch + "/404.html")
	http1cache   = []byte("Cache-Control: max-age=86400\r\n")
	http1nocache = []byte("Cache-Control: no-store, no-cache, must-revalidate, max-age=0, s-maxage=0\r\nPragma: no-cache\r\n")
)

func (r *Request) StaticHandler() gnet.Action {
	r.out.Reset()
	r.out1.Reset()
	etag := r.GetHeader("If-None-Match")
	filename := r.path
	if filename == "/" {
		filename = "/index.html"
	}

	isdeflate := strings.Contains(r.GetHeader("Accept-Encoding"), "deflate")
	var isgzip bool
	if !isdeflate {
		isgzip = strings.Contains(r.GetHeader("Accept-Encoding"), "gzip")
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
			r.out.Write(http1head304)
		} else if isdeflate && f_cache.iscompress { //deflate压缩资源
			r.out.Write(http1head200)
			r.out.WriteString("Content-Type: ")
			r.out.WriteString(f_cache.content_type)
			r.out.WriteString("\r\n")
			r.out.Write(http1deflate)
			r.out1.Write(f_cache.deflatefile)
		} else if isgzip && f_cache.iscompress { //gzip可压缩资源
			r.out.Write(http1head200)
			r.out.WriteString("Content-Type: ")
			r.out.WriteString(f_cache.content_type)
			r.out.WriteString("\r\n")
			r.out.Write(http1gzip)
			g := gzippool.Get().(*gzip.Writer)
			defer gzippool.Put(g)
			g.Reset(r.out1)
			g.Write(f_cache.file)
			g.Flush()
		} else { //非压缩资源
			r.out.Write(http1head200)
			r.out.WriteString("Content-Type: ")
			r.out.WriteString(f_cache.content_type)
			r.out.WriteString("\r\n")
			r.out1.Write(f_cache.file)
		}
		r.out.WriteString("Etag: ")
		r.out.WriteString(f_cache.etag)
		r.out.WriteString("\r\n")
		r.data = r.out1
		r.dataSize = r.out1.Len()
		return gnet.None
	} else {
		switch f_cache_err {
		case file_cache_err_NotFound:
			r.Out404()
		case file_cache_file_TooLarge:
			f, err := os.Open(filename)
			if err != nil {
				r.OutErr(err)
				return gnet.None
			}
			fstat, err := f.Stat()
			if err != nil {
				r.OutErr(err)
				return gnet.None
			}
			r.RangeDownload(f, fstat.Size(), filename)
		default:
			r.OutErr(errors.New("Unknown Error"))
		}

	}
	return gnet.None
}

type HttpIoReader interface {
	Seek(int64, int) (int64, error)
	Read([]byte) (int, error)
	Close() error
}

func (r *Request) RangeDownload(b HttpIoReader, size int64, name string) {
	r.out.Reset()
	var range_start, range_end int
	if r := r.GetHeader("range"); strings.Index(r, "bytes=") == 0 {
		if e := strings.Index(r, "-"); e > 6 {
			range_start, _ = strconv.Atoi(r[6:e])
			range_end, _ = strconv.Atoi(r[e+1:])
		}
	}
	if range_start > 0 || range_end > 0 {
		r.out.Write(http1head206)
		if range_end == 0 {
			range_end = int(size)
		}
		if _, e := b.Seek(int64(range_start), 0); e != nil {
			r.OutErr(e)
			return
		}
		r.out.WriteString("Content-Type: application/octet-stream\r\nAccept-Ranges: bytes\r\nContent-Range: bytes ")

		r.out.WriteString(strconv.Itoa(range_start))
		r.out.WriteString("-")
		r.out.WriteString(strconv.Itoa(range_end))
		r.out.WriteString("/")
		r.out.WriteString(strconv.Itoa(int(size)))
		r.out.WriteString("\r\n")
		r.out.WriteString(`Content-Disposition: attachment; filename*="utf8''` + url.QueryEscape(name) + `"` + "\r\n")
		r.data = b
		r.dataSize = range_end - range_start
	} else {
		r.out.Write(http1head200)
		r.out.WriteString("Content-Type: application/octet-stream\r\n")
		r.out.WriteString(`Content-Disposition: attachment; filename*="utf8''` + url.QueryEscape(name) + `"` + "\r\n")
		r.data = b
		r.dataSize = int(size)
	}
}
func (r *Request) Httpfinish() {
	if r.hs.ishttps {
		r.out.Write([]byte("strict-transport-security: max-age=31536000; includeSubDomains\r\n"))
	}
	for k, v := range r.outHeader {
		r.out.WriteString(k)
		r.out.WriteString(": ")
		r.out.WriteString(v)
		r.out.WriteString("\r\n")
	}

	for k, v := range r.outCookie {
		r.out.WriteString("Set-Cookie: ")
		r.out.WriteString(url.QueryEscape(k))
		r.out.WriteString("=")
		r.out.WriteString(url.QueryEscape(v.value))
		if v.max_age > 0 {
			r.out.WriteString("; Max-age=")
			r.out.WriteString(strconv.FormatUint(uint64(v.max_age), 10))
		}
		r.out.WriteString("; path=/\r\n")
	}
	if r.keep_alive {
		r.out.Write([]byte("Connection: keep-alive"))
	} else {
		r.out.Write([]byte("Connection: close"))
	}
	r.out.WriteString("\r\nContent-Length: ")
	r.out.WriteString(strconv.Itoa(r.dataSize))
	if r.dataSize > 0 {

		r.out.WriteString("\r\n\r\n")
		defer r.data.Close()
		for msglen := r.dataSize; msglen > 0; msglen = r.dataSize {
			if msglen > http2initialMaxFrameSize*100-r.out.Len() { //切分为一个tls包
				msglen = http2initialMaxFrameSize*100 - r.out.Len()
			}
			if _, e := r.data.Read(r.out.Make(msglen)); e != nil {
				DebugLog("httpsfinish Read错误%v", e)
				return
			}
			if r.dataSize > msglen {
				r.hs.c.FlushWrite(r.out.Bytes(), true)
			} else {
				r.connWrite(r.out.Bytes())
			}

			r.out.Reset()
			r.dataSize -= msglen
		}
	} else {
		r.out.WriteString("\r\n\r\n")
		r.connWrite(r.out.Bytes())
	}
	return
}
func (r *Request) Out404() {
	r.out.Reset()
	r.out1.Reset()
	r.out.WriteString("HTTP/1.1 404 Not Found\r\n")
	r.out1.Write(http404b)
	r.data = r.out1
	r.dataSize = r.out1.Len()
}

var Errfunc func(i interface{}, err error) bool

func (r *Request) OutErr(err error) {
	if Errfunc != nil {
		if Errfunc(r, err) {
			return
		}
	}
	r.out.Reset()
	r.out1.Reset()
	r.out.WriteString("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html;charset=utf-8\r\n")
	r.out1.WriteString(err.Error())
	r.data = r.out1
	r.dataSize = r.out1.Len()
}

func init() {

	if http404b == nil {
		http404b = []byte("404 not found")
	}
}

func (req *Request) Close() {
	req.hs.Close()
}

var sessionID = uint64(rand.NewSource(time.Now().Unix()).Int63())

func (r *Request) Session() *cache.Hashvalue {
	if r.hs.session == nil {
		//检查sessionID
		var has bool
		sessionIdKey := r.Cookie("sessionID")
		if sessionIdKey != "" {
			r.hs.session, has = cache.Has(sessionIdKey, "session")
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
			r.SetCookie("sessionID", sessionIdKey, 7*86400)
			r.hs.session = cache.Hget(sessionIdKey, "session")
			r.hs.session.Set("sessionID", sessionIdKey)
			r.hs.session.Expire(8 * 3600) //给个临时session
		}
	}
	return r.hs.session
}
func (r *Request) DelSession() {
	if r.hs.session != nil {
		r.hs.session.Hdel()
	}
}
func (r *Request) Body() []byte {
	return r.body
}
func (r *Request) Method() string {
	return r.method
}
func (r *Request) Header(name string) string {
	return r.header[name]
}
func (r *Request) SetHeader(name, value string) {
	r.outHeader[name] = value
}
func (r *Request) SetCookie(name, value string, max_age uint32) {
	r.outCookie[name] = httpcookie{
		value:   value,
		max_age: max_age,
	}
}
func (r *Request) Redirect(url string) {
	r.out.Reset()
	r.out.WriteString("HTTP/1.1 302 OK\r\nserver: gnet by luyu6056\r\nCache-Control: Max-age=0\r\nContent-Type: text/html;charset=utf-8\r\nLocation: ")
	r.out.WriteString(url)
	r.out.WriteString("\r\n")
	r.out1.Reset()
	r.data = r.out1
	r.dataSize = 0
}

func (r *Request) Cookie(name string) string {
	if cookieHead, ok := r.header["Cookie"]; ok {
		for _, cookie := range strings.Split(cookieHead, "; ") {
			if i := strings.Index(cookie, "="); i > 0 && cookie[:i] == name {
				v, _ := url.QueryUnescape(cookie[i+1:])
				return v
			}
		}
	}
	return ""
}
func (r *Request) Path() string {

	return r.path
}
func (r *Request) Query(key string) string {
	for _, q := range r.queryS {
		if q.key == key {
			return q.value[0]
		}
	}
	return ""
}

func (r *Request) Post(key string) (value string) {
	for _, q := range r.postS {
		if q.key == key {
			return q.value[0]
		}
	}
	return
}
func (r *Request) PostSlice(key string) []string {
	for _, q := range r.postS {
		if q.key == key {
			return q.value
		}
	}
	return nil
}
func (r *Request) GetAllPost() (res map[string][]string) {
	res = make(map[string][]string, len(r.postS))
	for _, v := range r.postS {
		res[v.key] = v.value
	}
	return res
}
func (r *Request) GetAllQuery() (res map[string][]string) {
	res = make(map[string][]string, len(r.queryS))
	for _, v := range r.queryS {
		res[v.key] = v.value
	}
	return res
}
func (r *Request) AddQuery(name, value string) {
	r.addquery(name, value)
}

func (r *Request) SetCode(code int) {
	r.outCode = code
}
func (r *Request) SetContentType(ContentType string) {
	r.outContentType = ContentType
}

type httpCode int

func (code httpCode) Bytes() []byte {
	return map[int][]byte{
		100: []byte("HTTP/1.1 100 Continue\r\n"),
		101: []byte("HTTP/1.1 101 Switching Protocols\r\n"),
		102: []byte("HTTP/1.1 102 Processing\r\n"),
		200: []byte("HTTP/1.1 200 OK\r\n"),
		201: []byte("HTTP/1.1 201 Created\r\n"),
		202: []byte("HTTP/1.1 202 Accepted\r\n"),
		203: []byte("HTTP/1.1 203 Non-Authoritative Information\r\n"),
		204: []byte("HTTP/1.1 204 No Content\r\n"),
		205: []byte("HTTP/1.1 205 Reset Content\r\n"),
		206: []byte("HTTP/1.1 206 Partial Content\r\n"),
		207: []byte("HTTP/1.1 207 Multi-Status\r\n"),
		300: []byte("HTTP/1.1 300 Multiple Choices\r\n"),
		301: []byte("HTTP/1.1 301 Moved Permanently\r\n"),
		302: []byte("HTTP/1.1 302 Move Temporarily\r\n"),
		303: []byte("HTTP/1.1 303 See Other\r\n"),
		304: []byte("HTTP/1.1 304 Not Modified\r\n"),
		305: []byte("HTTP/1.1 305 Use Proxy\r\n"),
		306: []byte("HTTP/1.1 306 Switch Proxy\r\n"),
		307: []byte("HTTP/1.1 307 Temporary Redirect\r\n"),
		400: []byte("HTTP/1.1 400 Bad Request\r\n"),
		401: []byte("HTTP/1.1 401 Unauthorized\r\n"),
		402: []byte("HTTP/1.1 402 Payment Required\r\n"),
		403: []byte("HTTP/1.1 403 Forbidden\r\n"),
		404: []byte("HTTP/1.1 404 Not Found\r\n"),
		405: []byte("HTTP/1.1 405 Method Not Allowed\r\n"),
		406: []byte("HTTP/1.1 406 Not Acceptable\r\n"),
		407: []byte("HTTP/1.1 407 Proxy Authentication Required\r\n"),
		408: []byte("HTTP/1.1 408 Request Timeout\r\n"),
		409: []byte("HTTP/1.1 409 Conflict\r\n"),
		410: []byte("HTTP/1.1 410 Gone\r\n"),
		411: []byte("HTTP/1.1 411 Length Required\r\n"),
		412: []byte("HTTP/1.1 412 Precondition Failed\r\n"),
		413: []byte("HTTP/1.1 413 Request Entity Too Large\r\n"),
		414: []byte("HTTP/1.1 414 Request-URI Too Long\r\n"),
		415: []byte("HTTP/1.1 415 Unsupported Media Type\r\n"),
		416: []byte("HTTP/1.1 416 Requested Range Not Satisfiable\r\n"),
		417: []byte("HTTP/1.1 417 Expectation Failed\r\n"),
		418: []byte("HTTP/1.1 418 I'm a teapot\r\n"),
		421: []byte("HTTP/1.1 421 Misdirected Request\r\n"),
		422: []byte("HTTP/1.1 422 Unprocessable Entity\r\n"),
		423: []byte("HTTP/1.1 423 Locked\r\n"),
		424: []byte("HTTP/1.1 424 Failed Dependency\r\n"),
		425: []byte("HTTP/1.1 425 Too Early\r\n"),
		426: []byte("HTTP/1.1 426 Upgrade Required\r\n"),
		449: []byte("HTTP/1.1 449 Retry With\r\n"),
		451: []byte("HTTP/1.1 451 Unavailable For Legal Reasons\r\n"),
		500: []byte("HTTP/1.1 500 Internal Server Error\r\n"),
		501: []byte("HTTP/1.1 501 Not Implemented\r\n"),
		502: []byte("HTTP/1.1 502 Bad Gateway\r\n"),
		503: []byte("HTTP/1.1 503 Service Unavailable\r\n"),
		504: []byte("HTTP/1.1 504 Gateway Timeout\r\n"),
		505: []byte("HTTP/1.1 505 HTTP Version Not Supported\r\n"),
		506: []byte("HTTP/1.1 506 Variant Also Negotiates\r\n"),
		507: []byte("HTTP/1.1 507 Insufficient Storage\r\n"),
		509: []byte("HTTP/1.1 509 Bandwidth Limit Exceeded\r\n"),
		510: []byte("HTTP/1.1 510 Not Extended\r\n"),
		600: []byte("HTTP/1.1 600 Unparseable Response Headers\r\n"),
	}[int(code)]
}
