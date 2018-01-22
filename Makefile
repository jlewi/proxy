## Copyright 2017 Istio Authors
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.

TOP := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

SHELL := /bin/bash
LOCAL_ARTIFACTS_DIR ?= $(abspath artifacts)
ARTIFACTS_DIR ?= $(LOCAL_ARTIFACTS_DIR)
BAZEL_STARTUP_ARGS ?=
BAZEL_BUILD_ARGS ?=
BAZEL_TEST_ARGS ?=
HUB ?=
TAG := $(shell date +v%Y%m%d)-$(shell git describe --tags --always --dirty)-$(shell git diff | sha256sum | cut -c -6)
BUILD_DIR=/tmp/build-${TAG}
IMAGE=gcr.io/kubeflow-rl/envoy:$(TAG)

docker:
	@mkdir -p $(BUILD_DIR)
	@cp -f bazel-bin/src/envoy/auth/envoy $(BUILD_DIR)
	@cp -f docker/Dockerfile.kubeflow $(BUILD_DIR)
	@docker build -t $(IMAGE) -f $(BUILD_DIR)/Dockerfile.kubeflow $(BUILD_DIR)
	@gcloud docker -- push  $(IMAGE)

build:
	@bazel $(BAZEL_STARTUP_ARGS) build $(BAZEL_BUILD_ARGS) //...

# Build only envoy - fast
build_envoy:
	bazel $(BAZEL_STARTUP_ARGS) build $(BAZEL_BUILD_ARGS) //src/envoy/mixer:envoy

clean:
	@bazel clean

test:
	bazel $(BAZEL_STARTUP_ARGS) test $(BAZEL_TEST_ARGS) //...
	bazel $(BAZEL_STARTUP_ARGS) test $(BAZEL_TEST_ARGS) --config=asan //...
	bazel $(BAZEL_STARTUP_ARGS) test $(BAZEL_TEST_ARGS) --config=clang-tsan //...

test_envoy:
	@bazel $(BAZEL_STARTUP_ARGS) test $(BAZEL_TEST_ARGS) //src/envoy/mixer/...

check:
	@script/check-license-headers
	@script/check-style

artifacts: build
	@script/push-debian.sh -c opt -p $(ARTIFACTS_DIR)

deb:
	bazel build tools/deb:istio-proxy  ${BAZEL_BUILD_ARGS}


.PHONY: build clean test check artifacts docker
