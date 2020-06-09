package libraries

//这里是用来替换json库或者其他序列化库

import (
	jsoniter "github.com/json-iterator/go"
)

func JsonUnmarshal(b []byte, i interface{}) error {
	return jsoniter.Unmarshal(b, i)
}
func JsonUnmarshalStr(s string, i interface{}) error {
	return jsoniter.UnmarshalFromString(s, i)
}
func JsonMarshal(i interface{}) []byte {
	b, e := jsoniter.Marshal(i)
	if e != nil {
		DEBUG(i, "json序列化失败", e)
	}
	return b
}
func JsonMarshalToString(i interface{}) string {
	s, e := jsoniter.MarshalToString(i)
	if e != nil {
		DEBUG(i, "json序列化失败", e)
	}
	return s
}
