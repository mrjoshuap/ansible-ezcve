#!/bin/sh
# Point Ansible at this checkout as mrjoshuap.ezcve.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
link_at() {
  parent=$1/ansible_collections/mrjoshuap
  mkdir -p "${parent}"
  ln -sfn "${root}" "${parent}/ezcve"
}
link_at "${root}/.ansible/collections"
if [ -n "${ANSIBLE_COLLECTIONS_PATH:-}" ]; then
  first=${ANSIBLE_COLLECTIONS_PATH%%:*}
  case "${first}" in
    "${root}/.ansible/collections") ;;
    *) link_at "${first}" ;;
  esac
fi
