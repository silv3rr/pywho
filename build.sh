#!/bin/sh

# Usage:
#   ./build.sh _WITH_ALTWHO _WITH_GEOIP _WITH_XXL

# Required: Python 3.7.3+, sysv-ipc, pyinstaller
#   python3 -m venv venv && . venv/bin/activate && \
#   pip3 install wheel setuptools sysv_ipc pyinstaller
# Recommended: upx
#   apt install upx-ucl or yum install upx

PYREQVER="3.7"
PYSRC="pywho.py"
PYINSTALLER=1
PACK=1
REQS="$(cut -d= -f1 requirements.txt 2>/dev/null)"
ARGS="--hidden-import sysv_ipc"
OPTS="_WITH_ALTWHO _WITH_SS5 _WITH_GEOIP _WITH_XXL"

if [ ! -s requirements.txt ] || [ -z "$REQS" ]; then
  echo "WARNING: missing requirements"
fi

for a in "$@"; do
  if echo "$a" | grep -iq -- "-h"; then
    printf "./%s %s\n" "$(basename "$0")" "$OPTS"
    exit 0
  fi
  if echo "$a" | grep -q "_WITH_GEOIP"; then
    ARGS="--hidden-import geoip2.webservice"
    REQS="$REQS geoip2"
  fi
  for o in $OPTS; do
    if echo "$a" | grep -q "$o"; then
      if grep -Eiq "^$a *= *false$" "$PYSRC"; then
        sed -i 's/^\('"$a"'\) *= *.*$/\1 = True/' "$PYSRC" &&
          echo "Set $a to: True"
      fi
    fi
  done
done

echo "Creating one single executable file..."

if [ -n "$VIRTUAL_ENV" ]; then
  echo "Running in venv: ${VIRTUAL_ENV}..."
else
  echo "Not running in venv..."
fi

if [ ! -e "$PYSRC" ]; then
  echo "ERROR: '$PYSRC' not found"
  exit 1
fi

command -V python3 || {
  echo "ERROR: python3 not found"
  exit 1
}
#command -V bc || { echo "ERROR: bc not found"; exit 1; }

PYVER="$(python3 --version | sed 's/.* \([0-9]\.[0-9]\{1,2\}\).*/\1/' | grep -E '^[0-9.]+$' || echo 0)"
PYVER_OK=0
#if command -V bc >/dev/null 2>&1; then
#  if [ "$(echo "$PYVER >= $PYREQVER" | bc)" -eq 1 ]; then
#    PYVER_OK=1
#  fi
#else
  PYVER_MAY="$(echo "$PYVER" | sed 's/\([0-9]\)\.[0-9]/\1/')"
  PYVER_MIN="$(echo "$PYVER" | sed 's/[0-9]\.\([0-9]\+\)/\1/')"
  PYREQVER_MAY="$(echo $PYREQVER | sed 's/\([0-9]\)\.[0-9]/\1/')"
  PYREQVER_MIN="$(echo $PYREQVER | sed 's/[0-9]\.\([0-9]\+\)/\1/')"
  if [ "$PYVER_MAY" -gt "$PYREQVER_MAY" ]; then
    PYVER_OK=1
  elif [ "$PYVER_MAY" -eq "$PYREQVER_MAY" ] && [ "$PYVER_MIN" -ge "$PYREQVER_MIN" ]; then
    PYVER_OK=1
  fi
#fi
if [ "$PYVER_OK" -eq 1 ]; then
  echo "python version is OK (need Python ${PYREQVER}+ got v${PYVER})"
else
  echo "WARNING: Python ${PYREQVER}+ not found"
fi

ECNT=0
for i in $REQS; do
  PKG="$( echo "$i" | tr '_' '-' )"
  printf "%b\n" 'try:\n  import '"${i}"'\nexcept:\n  exit(1)' | python3 || {
    echo "Module '${i}' not found, try 'apt install python3-${PKG}' or 'pip install ${PKG}'"
    ECNT=$((ECNT + 1))
  }
done
if [ "$ECNT" -gt 0 ]; then
  echo "ERROR: $ECNT module(s) missing"
  exit 1
fi

if [ "$PYINSTALLER" -eq 1 ]; then
  command -v pyinstaller >/dev/null 2>&1 || {
    echo "ERROR: pyinstaller not found, try 'apt install python3-pyinstaller' or 'pip install pyinstaller'"
    exit 1
  }
  pyinstaller pywho.py $ARGS --clean --noconfirm --onefile &&
    if [ -e "dist/pywho" ]; then
      printf "\nresult: OK "
      ls -la dist/pywho
      if [ "$PACK" -eq 1 ]; then
        . /etc/os-release
        PACKNAME="pywho-${ID:-linux}${VERSION_ID}-python${PYVER:-3}-x86_x64"
        printf "Creating %s.tar.gz...\n" "$PACKNAME"
        tar -C ./dist -cvf "${PACKNAME}.tar.gz" pywho >/dev/null &&
          sha512sum "${PACKNAME}.tar.gz" >"${PACKNAME}.sha512sum" && echo "shasum: OK" || echo "ERROR: shasum"
      fi
    else
      echo
      echo "ERROR: something went wrong :("
      exit 1
    fi
fi
