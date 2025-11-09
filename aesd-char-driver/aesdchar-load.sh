#!/bin/sh

### BEGIN INIT INFO
# Provides:          aesdchar
# Required-Start:    $local_fs
# Required-Stop:
# Default-Start:     S
# Default-Stop:
# Short-Description: Load aesdchar driver and create device node
### END INIT INFO

MODULE_NAME="aesdchar"
MODULE_PATH="/lib/modules/$(uname -r)/extra/aesdchar.ko"
DEVICE_PATH="/dev/aesdchar"

case "$1" in
  start)
        echo "Loading $MODULE_NAME module..."

        if [ ! -f "$MODULE_PATH" ]; then
            echo "ERROR: $MODULE_PATH not found"
            exit 1
        fi

        # load module
        insmod "$MODULE_PATH" || {
            echo "ERROR: Failed to load $MODULE_NAME"
            exit 1
        }

        # retrieve major number from /proc/devices
        MAJOR=$(grep "$MODULE_NAME" /proc/devices | awk '{print $1}')

        if [ -z "$MAJOR" ]; then
            echo "ERROR: Could not find major number for $MODULE_NAME"
            exit 1
        fi

        echo "Major number for $MODULE_NAME: $MAJOR"

        # remove old node if present
        [ -e "$DEVICE_PATH" ] && rm -f "$DEVICE_PATH"

        # create character device: major=<major>, minor=0
        mknod "$DEVICE_PATH" c "$MAJOR" 0
        chmod 666 "$DEVICE_PATH"

        echo "$MODULE_NAME device created at $DEVICE_PATH"
        ;;

  stop)
        echo "Stopping $MODULE_NAME..."

        # remove device node
        [ -e "$DEVICE_PATH" ] && rm -f "$DEVICE_PATH"

        # unload module
        rmmod "$MODULE_NAME" 2>/dev/null || echo "$MODULE_NAME not loaded"

        ;;

  restart)
        $0 stop
        sleep 1
        $0 start
        ;;

  *)
        echo "Usage: $0 {start|stop|restart}"
        exit 1
        ;;
esac

exit 0