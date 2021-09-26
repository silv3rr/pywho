#!/bin/sh

# Required: Python 3.7.3+, sysv-ipc, pyinstaller

# ./build.sh _WITH_ALTWHO _WITH_SPY _WITH_GEOIP

PYMINVER="3.7"
PYSRC="pywho.py"
PYINSTALLER=1
PACK=1
REQS=$(cut -d= -f1 requirements.txt)
ARGS="--hidden-import sysv_ipc"

if echo "$*" | grep -q "_WITH_SS5";  then
  sed -i 's/^\(_WITH_SS5 \?= \?\).*/\1 True/g' "$PYSRC"
fi
if echo "$*" | grep -q "_WITH_ALTWHO";  then
  sed -i 's/^\(_WITH_ALTWHO \?= \?\).*/\1 True/g' "$PYSRC"
fi
if echo "$*" | grep -q "_WITH_SPY";  then
  sed -i 's/^\(_WITH_SPY \?= \?\).*/\1 True/g' "$PYSRC"
fi
if echo "$*" | grep -q "_WITH_XXL";  then
  sed -i 's/^\(_WITH_XXL \?= \?\).*/\1 True/g' "$PYSRC"
fi
if echo "$*" | grep -q "_WITH_GEOIP";  then
  sed -i 's/^\(_WITH_GEOIP\? = \?\).*/\1 True/g' "$PYSRC"
  ARGS="--hidden-import geoip2.webservice"
  REQS="$REQS geoip2.webservice"
fi

echo "Creating one single executable file..."

if [ ! -e "$PYSRC" ]; then
  echo "ERROR: '$PYSRC' not found"; exit 1
fi

command -V python3 || { echo "ERROR: python3 not found"; exit 1; }
{ python3 --version | grep -q "$PYMINVER"; } || echo "WARNING: Python $PYMINVER not found"

ECNT=0
for i in $REQS; do
  printf "%b\n" 'try:\n  import '"${i}"'\nexcept:\n  exit(1)' | python3 || { \
    echo "Module '${i}' not found, try 'yum/apt install python3-${i}' or 'pip install ${i}'"
    ECNT=$((ECNT+1))
  }
done
if [ "$ECNT" -gt 0 ]; then
  echo "ERROR: $ECNT module(s) missing"
  exit 1;
fi

if [ "$PYINSTALLER" -eq 1 ]; then
  command -v pyinstaller || { \
    echo "ERROR: pyinstaller not found, try 'pip install pyinstaller'"; exit 1; \
  }
  pyinstaller pywho.py $ARGS --noconfirm --onefile && \
    if [ -e "dist/pywho" ]; then
      printf "\nOK: "; ls -la dist/pywho;
      if [ "$PACK" -eq 1 ]; then
        . /etc/os-release
        PACKNAME="pywho-${ID:-linux}-python3-x86_x64"
        printf "Creating %s.tar.gz...\n" "$PACKNAME"
        tar -C ./dist -cvf "${PACKNAME}.tar.gz" pywho && \
        sha512sum "${PACKNAME}.tar.gz" > "${PACKNAME}.sha512sum" && echo "OK" || echo "ERROR: shasum"
      fi
    else
      echo; echo "ERROR: something went wrong :("; exit 1;
    fi
fi

