module tcpfan

go 1.15

require (
	github.com/dlclark/regexp2 v1.4.0
	github.com/json-iterator/go v1.1.11
	github.com/klauspost/compress v1.14.2
	github.com/luyu6056/gnet v1.3.6
	github.com/luyu6056/tls v0.15.1
	github.com/panjf2000/ants/v2 v2.4.7
	server/codec v0.0.0-00010101000000-000000000000
	server/config v0.0.0-00010101000000-000000000000
)

replace server/codec => ./codec

replace server/config => ./config
