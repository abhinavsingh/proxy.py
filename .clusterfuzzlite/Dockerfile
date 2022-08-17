FROM gcr.io/oss-fuzz-base/base-builder-python

COPY . $SRC/
WORKDIR $SRC/proxy
COPY .clusterfuzzlite/build.sh $SRC/