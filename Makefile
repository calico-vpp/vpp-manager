.PHONY: all build image

all: build image


build:
	GOOS=linux go build


image: build
	docker build --pull --build-arg http_proxy=${DOCKER_BUILD_PROXY} -t calicovpp/vpp:latest .


