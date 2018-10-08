.PHONY: proto

proto: 
	protoc $$PROTO_PATH --go_out=. pb/flow.proto
