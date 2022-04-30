#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

terminate_kubearmor() {
    pid=$(ps -e | grep kubearmor | awk '{print $1}')
    if [ "$pid" != "" ]; then
        kill -SIGTERM $pid
    fi
    exit
}
trap terminate_kubearmor EXIT SIGTERM SIGKILL

DEBUG=0
ARMOR_OPTIONS=${@:1}

case $1 in
    "-DEBUG")
        DEBUG=1
        ARMOR_OPTIONS=${@:2}
        ;;
    *)
        ;;
esac

cd /KubeArmor/BPF
make

for ((i=0;i<5;i++))
do
    /KubeArmor/kubearmor ${ARMOR_OPTIONS[@]}
    ERROR_CODE=$?

    if [ $ERROR_CODE != 0 ]; then
        echo "Error code:" $ERROR_CODE
    fi
done

if [ $DEBUG == 1 ]; then
    tail -f /dev/null
fi
