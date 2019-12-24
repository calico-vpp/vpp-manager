.PHONY: all build image

all: build image


build:
	GOOS=linux go build


image:
	docker build -t calicovpp/vpp:latest .


