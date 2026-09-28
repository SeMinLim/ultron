#!/bin/bash
make -C cpp bsim

./bsim/obj/bsim &
export BDBM_BSIM_PID=$!
echo "running host (sw or cpp/obj/bsim)"
echo $BDBM_BSIM_PID
sleep 1
HOST=./sw
[ -x "$HOST" ] || HOST=./cpp/obj/bsim
if [ "$1" == "gdb" ]
then
	gdb "$HOST"
else
	"$HOST" "$@"
fi
kill $BDBM_BSIM_PID 2>/dev/null
sleep 0.5
kill -9 $BDBM_BSIM_PID 2>/dev/null
rm -f /dev/shm/bdbm$BDBM_BSIM_PID
