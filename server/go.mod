module tcpfan

go 1.14

require (
	github.com/dlclark/regexp2 v1.2.0
	github.com/json-iterator/go v1.1.9
	github.com/klauspost/compress v1.10.10
	github.com/luyu6056/gnet v1.2.4
	github.com/luyu6056/gnet/tls v0.0.0-20200320144348-db512f05f945
	github.com/luyu6056/tls v0.0.1
	github.com/panjf2000/ants/v2 v2.4.1
	golang.org/x/net v0.0.0-20200707034311-ab3426394381
	server/codec v0.0.0-00010101000000-000000000000
	server/config v0.0.0-00010101000000-000000000000
)

replace server/codec => ./codec

replace server/config => ./config
