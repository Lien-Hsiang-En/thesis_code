#!/bin/bash
#
# test.sh - Performance Test Script for eBPF Container Network Acceleration
#
# Usage:
#   sudo ./scripts/test.sh [--quick] [--full]

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${PROJECT_DIR}/results"
LOADER="${PROJECT_DIR}/loader"

PING_COUNT=100
IPERF_DURATION=10

CONTAINER_1="test-perf-1"
CONTAINER_2="test-perf-2"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_test() { echo -e "${BLUE}[TEST]${NC} $1"; }
log_result() { echo -e "${YELLOW}[RESULT]${NC} $1"; }

check_requirements() {
    log_info "Checking requirements..."
    
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
    
    for tool in docker ping iperf3; do
        if ! command -v $tool &> /dev/null; then
            echo "Required tool not found: $tool"
            exit 1
        fi
    done
    
    if [[ ! -f "$LOADER" ]]; then
        echo "Loader not found. Please run 'make loader' first."
        exit 1
    fi
}

get_veth_name() {
    local container=$1
    local pid=$(docker inspect -f '{{.State.Pid}}' $container)
    local peer_ifindex=$(nsenter -t $pid -n cat /sys/class/net/eth0/iflink)
    grep -l "^$peer_ifindex$" /sys/class/net/veth*/ifindex 2>/dev/null | \
        sed 's|/sys/class/net/||;s|/ifindex||' | head -1
}

setup_containers() {
    log_info "Setting up test containers..."
    
    docker rm -f $CONTAINER_1 $CONTAINER_2 2>/dev/null || true
    
    docker run -d --name $CONTAINER_1 networkstatic/iperf3 -s
    docker run -d --name $CONTAINER_2 networkstatic/iperf3 -s
    
    sleep 2
    
    IP1=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $CONTAINER_1)
    IP2=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $CONTAINER_2)
    VETH1=$(get_veth_name $CONTAINER_1)
    VETH2=$(get_veth_name $CONTAINER_2)
    
    log_info "Container 1: $IP1 via $VETH1"
    log_info "Container 2: $IP2 via $VETH2"
}

cleanup_containers() {
    log_info "Cleaning up containers..."
    docker rm -f $CONTAINER_1 $CONTAINER_2 2>/dev/null || true
}

enable_acceleration() {
    log_info "Enabling eBPF acceleration..."
    $LOADER attach $VETH1 || true
    $LOADER attach $VETH2 || true
    $LOADER add $IP1 $VETH1
    $LOADER add $IP2 $VETH2
}

disable_acceleration() {
    log_info "Disabling eBPF acceleration..."
    $LOADER del $IP1 2>/dev/null || true
    $LOADER del $IP2 2>/dev/null || true
    $LOADER detach $VETH1 2>/dev/null || true
    $LOADER detach $VETH2 2>/dev/null || true
}

run_ping_test() {
    local mode=$1
    log_test "Running ping test ($mode)..."
    
    local output=$(docker exec $CONTAINER_1 ping -c $PING_COUNT -i 0.01 $IP2 2>&1)
    local avg=$(echo "$output" | grep -oP 'rtt min/avg/max/mdev = [\d.]+/\K[\d.]+')
    
    log_result "Ping $mode: avg=${avg}ms"
    echo "$mode,$avg" >> "${RESULTS_DIR}/ping.csv"
}

run_iperf_test() {
    local mode=$1
    log_test "Running iperf3 TCP test ($mode)..."
    
    local output=$(docker exec $CONTAINER_1 iperf3 -c $IP2 -t $IPERF_DURATION -J 2>&1)
    local bps=$(echo "$output" | jq -r '.end.sum_sent.bits_per_second // 0')
    local gbps=$(echo "scale=2; $bps / 1000000000" | bc)
    
    log_result "TCP $mode: ${gbps} Gbps"
    echo "$mode,$gbps" >> "${RESULTS_DIR}/throughput.csv"
}

run_quick_tests() {
    mkdir -p "$RESULTS_DIR"
    
    log_info "=== Baseline Tests ==="
    disable_acceleration
    sleep 1
    run_ping_test "baseline"
    run_iperf_test "baseline"
    
    log_info "=== Accelerated Tests ==="
    enable_acceleration
    sleep 1
    run_ping_test "accelerated"
    run_iperf_test "accelerated"
    
    disable_acceleration
    
    log_info "=== Results ==="
    echo "Ping Results:"
    cat "${RESULTS_DIR}/ping.csv"
    echo ""
    echo "Throughput Results:"
    cat "${RESULTS_DIR}/throughput.csv"
}

main() {
    check_requirements
    setup_containers
    
    trap cleanup_containers EXIT
    
    run_quick_tests
    
    log_info "Tests complete!"
}

main "$@"