#!/usr/bin/env bash

set -e

echo "\nHOME=$HOME" >> /etc/sysconfig/kubearmor.conf

/bin/systemctl daemon-reload
/bin/systemctl start kubearmor.service
