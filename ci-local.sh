#!/bin/sh

# build in local docker container, similar to github workflow

# run latest images by default
TAG="${2:-latest}"

# add post build commands
CLEANUP="
  test -e venv/pyvenv.cfg && rm -rf venv
  test -e build/spy && rm -rf build
"

UBUNTU="
  python3 -m venv venv && . venv/bin/activate
  pip3 install --upgrade pip wheel setuptools
  pip3 install -r requirements.txt
  pip3 install pyinstaller sysv-ipc geoip2 flask
  ./build.sh && mkdir -p ./build-ubuntu && mv -f *.tar.gz *.sha512sum ./build-ubuntu
"
DEBIAN="
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y wget python3 python3-venv python3-pip
  python3 -m venv venv && . venv/bin/activate
  pip3 install --upgrade pip wheel setuptools
  pip3 install --force -r requirements.txt
  pip3 install --force pyinstaller sysv-ipc geoip2 flask
  ./build.sh && mkdir -p ./build-debian && mv -f *.tar.gz *.sha512sum ./build-debian
  ./build.sh _WITH_BUNDLE && mkdir -p ./build-debian && mv -f *.tar.gz *.sha512sum ./build-debian
"
_CENTOS_EOL="
  yum install -y gcc python3-devel python3-pip python3-virtualenv
  python3 -m venv venv && . venv/bin/activate
  pip3 install --upgrade pip wheel setuptools
  pip3 install -r requirements.txt
  pip3 install pyinstaller sysv-ipc geoip2
  ./build.sh  && mkdir -p ./build-centos && mv -f *.tar.gz *.sha512sum ./build-centos
"
ALPINE="
  apk add python3 python3-dev py3-pip py3-virtualenv gcc musl-dev
  python3 -m venv venv && . venv/bin/activate
  pip3 install --upgrade pip wheel setuptools
  pip3 install -r requirements.txt
  pip3 install pyinstaller sysv-ipc geoip2 flask
  ./build.sh && mkdir -p ./build-alpine && mv -f *.tar.gz *.sha512sum ./build-alpine
  ./build.sh _WITH_BUNDLE && mkdir -p ./build-alpine && mv -f *.tar.gz *.sha512sum ./build-alpine
"
RHEL="
  dnf install -y gcc python3-devel python3-pip
  dnf install -y epel-release
  python3 -m venv venv && . venv/bin/activate
  pip3 install --upgrade pip wheel setuptools
  pip3 install -r requirements.txt
  pip3 install pyinstaller sysv-ipc geoip2
  ./build.sh && mkdir ./build-$1 && mv -f *.tar.gz *.sha512sum ./build-$1
"

func_docker_run() {
  image=$1
  shift
  if [ -n "$DEBUG" ] && [ "$DEBUG" -eq 1 ]; then
    docker run -it --pull always --workdir /build -v "$PWD:/build" "$image" sh
  else
    docker run --rm --pull always --workdir /build -v "$PWD:/build" "$image" sh -c "
      $*
      $CLEANUP
    "
  fi
}

# shellcheck disable=SC2046
case $1 in
  ubuntu) func_docker_run "ubuntu:$TAG" "$UBUNTU" ;;
  #debian) func_docker_run "debian:$TAG" "$DEBIAN" ;;
  debian) func_docker_run "python:$TAG" "$DEBIAN" ;;
  #centos7) func_docker_run centos:7 "$_CENTOS_EOL" ;;
  centos-stream) func_docker_run "quay.io/centos/centos:$TAG" "$RHEL" ;;
  alma) func_docker_run "almalinux:$TAG" "$RHEL" ;;
  rocky) func_docker_run "rockylinux:$TAG" "$RHEL" ;;
  alpine) func_docker_run "alpine:$TAG" "$ALPINE" ;;
  *) printf "USAGE: %s <%s>\n" "$0" "$(grep -Pow ' \K[a-z-]+\)' "$0" | sed 's/)//g' | sed ':a;N;$!ba;s/\n/|/g')" ;;
esac
