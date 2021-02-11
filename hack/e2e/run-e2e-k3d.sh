#!/usr/bin/env bash

##
## This file is part of Cloud Native PostgreSQL.
##
## Copyright (C) 2019-2021 EnterpriseDB Corporation.
##

# standard bash error handling
set -eEuo pipefail;

if [ "${DEBUG-}" = true ]; then
    set -x
fi


ROOT_DIR=$(realpath "$(dirname "$0")/../../")
HACK_DIR="${ROOT_DIR}/hack"
E2E_DIR="${HACK_DIR}/e2e"

export PRESERVE_CLUSTER=${PRESERVE_CLUSTER:-false}
export BUILD_IMAGE=${BUILD_IMAGE:-false}
export K8S_VERSION=${K8S_VERSION:-v1.20.0}
export KUBECTL_VERSION=${KUBECTL_VERSION:-$K8S_VERSION}
export CLUSTER_NAME=pg-operator-e2e-${K8S_VERSION//./-}
export TEMP_DIR=$(mktemp -d)
export LOG_DIR=${LOG_DIR:-$ROOT_DIR/_logs/}

export CONTROLLER_IMG=${CONTROLLER_IMG:-quay.io/enterprisedb/cloud-native-postgresql-testing:$( (git symbolic-ref -q --short HEAD || git describe --tags --exact-match) | tr / -)}
export POSTGRES_IMG=${POSTGRES_IMG:-$(grep 'DefaultImageName.*=' "${ROOT_DIR}/pkg/versions/versions.go" | cut -f 2 -d \")}
export E2E_PRE_ROLLING_UPDATE_IMG=${E2E_PRE_ROLLING_UPDATE_IMG:-${POSTGRES_IMG%.*}}
export E2E_DEFAULT_STORAGE_CLASS=${E2E_DEFAULT_STORAGE_CLASS:-local-path}

export DOCKER_REGISTRY_MIRROR=${DOCKER_REGISTRY_MIRROR:-}

KUBECTL="${TEMP_DIR}/kubectl"

install_go_tools_k3d() {
    local GO_TMP_DIR
    GO_TMP_DIR=$(mktemp -d)
    cd "$GO_TMP_DIR"
    go mod init tmp
    go get -u github.com/onsi/ginkgo/ginkgo
    rm -rf "$GO_TMP_DIR"
    cd -
    PATH="$(go env GOPATH)/bin:${PATH}"
    export PATH
}

cleanup() {
    if [ "${PRESERVE_CLUSTER}" = false ]; then
        k3d cluster delete "${CLUSTER_NAME}" || true
        rm -rf "${TEMP_DIR}"
    else
        set +x
        echo "You've chosen not to delete the Kubernetes cluster."
        echo "You can delete it manually later running:"
        echo "k3d cluster delete ${CLUSTER_NAME}"
        echo "rm -rf ${TEMP_DIR}"
    fi
}

trap cleanup EXIT

main() {
    install_go_tools_k3d

    if [ "${BUILD_IMAGE}" == false ]; then
        export DOCKER_SERVER
        export DOCKER_USERNAME
        export DOCKER_PASSWORD
    else
        export CONTROLLER_IMG=cloud-native-postgresql:e2e
    fi

    eval CLUSTER_ENGINE=k3d ${HACK_DIR}/setup-cluster.sh

    ${KUBECTL} apply -f "${E2E_DIR}/kind-fluentd.yaml"
    # Run the tests and destroy the cluster
    # Do not fail out if the tests fail. We want the logs anyway.
    ITER=0
    #Number of nodes need to be changed if cluster nodes are more than 4
    NODE=4
    while true; do
      NUMBERREADY=$(${KUBECTL} get ds fluentd -n kube-system -ojsonpath='{.status.numberReady}')
      ITER=$((ITER + 1))
      sleep 5
      if [[ $ITER -gt 60 ]]; then
        echo "Time out"
        exit 1
      fi
      if [[ $NUMBERREADY == $NODE ]]; then
        echo "FluentD is Ready"
        break
      fi
    done
    RC=0
    ${E2E_DIR}/run-e2e.sh || RC=$?

    ## Export logs
    while IFS= read -r line
    do
        NODES_LIST+=("$line")
    done < <(k3d node list | awk 'NR > 1 {print $1}')
    for i in "${NODES_LIST[@]}"; do
      mkdir -p ${LOG_DIR}/${i}
      docker cp -L $i:/var/log/. ${LOG_DIR}/${i}
    done

    if [ "${PRESERVE_CLUSTER}" = false ]; then
        k3d cluster delete ${CLUSTER_NAME}
    fi
    exit $RC
}


main
