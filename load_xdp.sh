#!/bin/bash

set -e

PIN_PATH="/sys/fs/bpf/geo"
IFACE="ens160"
OBJ="xdp_geo.o"
SECTION="xdp_geo_filter"

echo "Проверка, что BPF файловая система смонтирована..."
if ! mountpoint -q /sys/fs/bpf; then
    echo "BPF файловая система не смонтирована. Монтируем..."
    mount -t bpf none /sys/fs/bpf
fi

echo "Снятие с интерфейса $IFACE"
sudo ip link set dev "$IFACE" xdp off

echo "Удаление старого $PIN_PATH"
rm -rf "$PIN_PATH"
mkdir -p "$PIN_PATH"

echo "Загрузка $OBJ и пиннинг карт..."

bpftool prog loadall "$OBJ" "$PIN_PATH" type xdp pinmaps "$PIN_PATH"

echo "Инициализация конфигурации гео-фильтрации..."

sudo bpftool map update pinned "$PIN_PATH/cfg_geo_m" \
    key hex 00 00 00 00 \
    value hex \
    $(for i in {1..128}; do echo -n "00 "; done) \
    $(for i in {1..128}; do echo -n "00 "; done) \
    00 00 00 00

echo "Привязка XDP к интерфейсу $IFACE"
ip link set dev "$IFACE" xdpgeneric pinned "$PIN_PATH/$SECTION"

echo "Загрузка и конфигурация завершены."

