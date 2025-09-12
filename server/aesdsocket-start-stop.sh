#!/bin/sh
### BEGIN INIT INFO
# Provides:          aesdsocket
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: AESD socket server
### END INIT INFO

DAEMON=/usr/bin/aesdsocket
NAME=aesdsocket
DESC="AESD socket server"

case "$1" in
  start)
    echo "Starting $DESC..."
    start-stop-daemon -S -n $NAME -a $DAEMON -- -d
    ;;
  stop)
    echo "Stopping $DESC..."
    start-stop-daemon -K -n $NAME
    ;;
  restart)
    echo "Restarting $DESC..."
    $0 stop
    $0 start
    ;;
  status)
    pidof $NAME >/dev/null && echo "$DESC is running" || echo "$DESC is not running"
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}"
    exit 1
    ;;
esac

exit 0
