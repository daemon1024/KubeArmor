#!/bin/bash
# Copyright 2021 Authors of KubeArmor
# SPDX-License-Identifier: Apache-2.0


ARMOR_HOME=`dirname $(realpath "$0")`/..

mkdir -p $ARMOR_HOME/build/KubeArmor

# copy files to build
cp -r $ARMOR_HOME/BPF/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/audit/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/common/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/core/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/discovery/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/enforcer/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/feeder/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/log/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/monitor/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/templates/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/types/ $ARMOR_HOME/build/KubeArmor/
cp $ARMOR_HOME/go.mod $ARMOR_HOME/build/KubeArmor/
cp $ARMOR_HOME/main.go $ARMOR_HOME/build/KubeArmor/

# copy patch.sh
cp $ARMOR_HOME/build/patch.sh $ARMOR_HOME/build/KubeArmor/
cp $ARMOR_HOME/build/patch_selinux.sh $ARMOR_HOME/build/KubeArmor/

# copy GKE files
cp -r $ARMOR_HOME/../GKE $ARMOR_HOME/build/

# copy protobuf
cp -r $ARMOR_HOME/../protobuf $ARMOR_HOME/build/

# copy CRDs
cp $ARMOR_HOME/../pkg/KubeArmorPolicy/config/crd/bases/security.kubearmor.com_kubearmorpolicies.yaml KubeArmorPolicy.yaml
cp $ARMOR_HOME/../pkg/KubeArmorHostPolicy/config/crd/bases/security.kubearmor.com_kubearmorhostpolicies.yaml KubeArmorHostPolicy.yaml
