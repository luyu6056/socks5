package libraries

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/klauspost/compress/gzip"

	"github.com/dlclark/regexp2"
	"github.com/luyu6056/gnet/buf"
)

var MsgBuf_chan = make(chan *buf.MsgBuffer, runtime.NumCPU())

func init() {
	go func() {
		err := http.ListenAndServe("0.0.0.0:8081", nil)
		if err != nil {
			http.ListenAndServe("0.0.0.0:8082", nil)
		}

	}()

	for i := 0; i < runtime.NumCPU(); i++ {

		MsgBuf_chan <- &buf.MsgBuffer{}

		gzip_writer := new(Gzip_writer)
		gzip_writer.Buf = new(buf.MsgBuffer)
		gzip_writer.Writer, _ = gzip.NewWriterLevel(gzip_writer.Buf, 6)
		gzipcompress_chan <- gzip_writer

	}

}

type Buffer_reader struct {
	b *bytes.Buffer
}
type Gzip_writer struct {
	Buf    *buf.MsgBuffer
	Writer *gzip.Writer
}

var uncompress_chan = make(chan *bytes.Buffer, runtime.NumCPU())
var gzipcompress_chan = make(chan *Gzip_writer, runtime.NumCPU())

func Str2bytes(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s))
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h))
}

func Bytes2str(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

const hextable = "0123456789abcdef"

func MD5_S(str string) string {
	dst := make([]byte, 32)
	for k, v := range md5.Sum(Str2bytes(str)) {
		dst[k*2] = hextable[v>>4]
		dst[k*2+1] = hextable[v&0x0f]
	}
	return Bytes2str(dst)
}
func MD5_S_B(str string) []byte {
	dst := make([]byte, 32)
	for k, v := range md5.Sum(Str2bytes(str)) {
		dst[k*2] = hextable[v>>4]
		dst[k*2+1] = hextable[v&0x0f]
	}
	return dst
}
func MD5_B(b []byte) string {
	dst := make([]byte, 32)
	for k, v := range md5.Sum(b) {
		dst[k*2] = hextable[v>>4]
		dst[k*2+1] = hextable[v&0x0f]
	}
	return Bytes2str(dst)
}
func SHA256_S(str string) string {
	dst := make([]byte, 64)
	for k, v := range sha256.Sum256(Str2bytes(str)) {
		dst[k*2] = hextable[v>>4]
		dst[k*2+1] = hextable[v&0x0f]
	}
	return Bytes2str(dst)
}
func GetFileModTime(path string) int64 {
	f, err := os.Open(path)
	if err != nil {
		log.Println("open file error")
		return time.Now().Unix()
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		log.Println("stat fileinfo error")
		return time.Now().Unix()
	}

	return fi.ModTime().Unix()
}

//返回int64时间戳
func Timestampint() int64 {
	cur := time.Now()
	return cur.Unix()
}

//返回匹配结果,n=次数
func Preg_match_result(regtext string, text string, n int) ([][]string, error) {

	r, err := regexp2.Compile(regtext, 0)
	if err != nil {
		return nil, err
	}

	m, err := r.FindStringMatch(text)
	if err != nil {
		return nil, err
	}
	var result [][]string
	for m != nil && n != 0 {
		var res_v []string
		for _, v := range m.Groups() {
			res_v = append(res_v, v.String())
		}

		m, _ = r.FindNextMatch(m)
		result = append(result, res_v)
		n--
	}

	return result, nil
}

//获取指定目录下的所有文件，不进入下一级目录搜索，可以匹配后缀过滤。
func ListDir(dirPth string, suffix string) (files []string, err error) {
	files = make([]string, 0, 10)
	dir, err := ioutil.ReadDir(dirPth)
	if err != nil {
		return nil, err
	}
	PthSep := "/"
	if os.IsPathSeparator('\\') { //前边的判断是否是系统的分隔符
		PthSep = "\\"
	}
	suffix = strings.ToUpper(suffix) //忽略后缀匹配的大小写
	for _, fi := range dir {
		if fi.IsDir() { // 忽略目录
			continue
		}
		if strings.HasSuffix(strings.ToUpper(fi.Name()), suffix) { //匹配文件
			files = append(files, dirPth+PthSep+fi.Name())
		}
	}
	return files, nil
}
func DogzipUnCompress(compressSrc []byte) []byte {
	b := <-uncompress_chan
	defer func() {
		uncompress_chan <- b
	}()
	b.Reset()
	b.Write(compressSrc)
	r, err := gzip.NewReader(b)
	if err != nil {
		return nil
	}
	defer r.Close()
	ndatas, err := ioutil.ReadAll(r)
	res := make([]byte, len(ndatas))
	copy(res, ndatas)
	if err != nil {
		return res
	}
	return res
}
func CopyFile(srcName, dstName string) (written int64, err error) {

	src, err := os.Open(srcName)
	if err != nil {
		return
	}
	defer src.Close()
	dst, err := os.OpenFile(dstName, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer dst.Close()
	return io.Copy(dst, src)
}

//把字串符转为指定小数点的字串符
func Number_format(s interface{}, d interface{}) string {
	var f float64
	var decimals string
	switch d.(type) {
	case string:
		decimals = d.(string)
	case int:
		decimals = strconv.Itoa(d.(int))
	case int64:
		decimals = strconv.FormatInt(d.(int64), 10)
	default:
		t := reflect.TypeOf(d)
		fmt.Println("Number_format decimals无法识别变量类型", t.Name())
	}

	switch s.(type) {
	case string:
		f, _ = strconv.ParseFloat(s.(string), 64)
	case int:
		f = float64(s.(int))
	case int32:
		f = float64(s.(int32))
	case int64:
		f = float64(s.(int64))
	case float32:
		f = float64(s.(float32))
	case float64:
		f = s.(float64)
	default:
		t := reflect.TypeOf(s)
		fmt.Println("Number_format float无法识别变量类型", t.Name())
	}

	return fmt.Sprintf("%."+decimals+"f", f)
}

//正则替换
func Preg_replace(regtext string, text string, src string) (string, error) {
	r, _ := regexp2.Compile(regtext, 0)
	return r.Replace(src, text, -1, -1)

}
