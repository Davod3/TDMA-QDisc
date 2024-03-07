# TC Documentation

## Build
```
export SRC_DIR=/path/to/iproute2
export LIB_DIR=/usr/lib
export TC_LIB_DIR=${LIB_DIR}/tc

cd ${SRC_DIR}
./configure
make TCSO=q_tbf_test.so

mkdir -p ${LIB_DIR}/tc
cp ./tc/q_tbf_test.so ${TC_LIB_DIR}
```
