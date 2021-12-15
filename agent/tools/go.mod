module tools

go 1.17

replace github.com/bytedance/Elkeid/agent v1.0.0 => ../

require google.golang.org/grpc v1.43.0

require (
	github.com/bytedance/Elkeid/agent v1.0.0
	github.com/golang/protobuf v1.5.2 // indirect
	golang.org/x/net v0.0.0-20210503060351-7fd8e65b6420 // indirect
	golang.org/x/sys v0.0.0-20210823070655-63515b42dcdf // indirect
	golang.org/x/text v0.3.6 // indirect
	google.golang.org/genproto v0.0.0-20210828152312-66f60bf46e71 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)

require (
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/uuid v1.3.0
)
