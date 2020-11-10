#!/bin/sh

set -e

if [ "$1" = "configure" ]; then
  if [ "$2" = "" ]; then
    # install
    systemctl enable mced.service >/dev/null 2>&1 || :
    if [ -d /run/systemd/system ]; then
      systemctl start mced.service >/dev/null 2>&1 || :
    fi
  else
    # upgrade
    if [ -d /run/systemd/system ]; then
      systemctl try-restart mced.service >/dev/null 2>&1 || :
    fi
  fi
elif [ "$1" = "remove" ]; then
  # uninstall
  systemctl --no-reload disable mced.service >/dev/null 2>&1 || :
  if [ -d /run/systemd/system ]; then
    systemctl stop mced.service >/dev/null 2>&1 || :
  fi
else
  # abort-upgrade, abort-remove, upgrade, failed-upgrade
  :
fi

exit 0
