#!/usr/bin/env python3
"""
container_manager.py - Docker Container Network Manager

This script monitors Docker events and automatically manages BPF map entries
for container network acceleration. It:
1. Listens for container start/stop events
2. Extracts container IP and veth interface information
3. Updates the BPF map accordingly
4. Attaches/detaches TC BPF programs to veth interfaces

Requirements:
    pip install docker pyroute2

Usage:
    sudo python3 container_manager.py [--network bridge] [--debug]
"""

import argparse
import logging
import os
import re
import signal
import subprocess
import sys
import time
from typing import Dict, Optional, Tuple

try:
    import docker
    from docker.models.containers import Container
except ImportError:
    print("Error: docker package required. Install with: pip install docker")
    sys.exit(1)

try:
    from pyroute2 import IPRoute
except ImportError:
    print("Error: pyroute2 package required. Install with: pip install pyroute2")
    sys.exit(1)

# Paths
LOADER_PATH = "./loader"

# Container info cache
container_cache: Dict[str, dict] = {}

# Logger setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def find_veth_pair(pid: int, container_id: str = None) -> Tuple[Optional[str], Optional[int]]:
    """
    Find the host-side veth interface for a container by its PID.
    
    This works by:
    1. Looking up the container's eth0 interface and finding @ifXXX peer index
    2. Finding the corresponding veth on the host by that ifindex
    """
    try:
        # Method 1: Use docker exec to get the peer ifindex from eth0@ifXXX
        if container_id:
            try:
                result = subprocess.run(
                    ['docker', 'exec', container_id, 'ip', 'link', 'show', 'eth0'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    # Parse "35945: eth0@if35946:" to get 35946
                    match = re.search(r'@if(\d+):', result.stdout)
                    if match:
                        peer_ifindex = int(match.group(1))
                        # Find the veth name on host by ifindex
                        with IPRoute() as ipr:
                            links = ipr.get_links(peer_ifindex)
                            if links:
                                ifname = links[0].get_attr('IFLA_IFNAME')
                                return ifname, peer_ifindex
            except Exception as e:
                logger.debug(f"docker exec method failed: {e}")
        
        # Method 2: Use nsenter to read from /proc
        try:
            result = subprocess.run(
                ['nsenter', '-t', str(pid), '-n', 'ip', 'link', 'show', 'eth0'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                match = re.search(r'@if(\d+):', result.stdout)
                if match:
                    peer_ifindex = int(match.group(1))
                    with IPRoute() as ipr:
                        links = ipr.get_links(peer_ifindex)
                        if links:
                            ifname = links[0].get_attr('IFLA_IFNAME')
                            return ifname, peer_ifindex
        except Exception as e:
            logger.debug(f"nsenter method failed: {e}")
        
    except Exception as e:
        logger.debug(f"Error finding veth pair: {e}")
    
    return None, None


def get_container_info(container: Container, network: str) -> Optional[dict]:
    """
    Extract network information from a container.
    
    Returns:
        dict with 'ip', 'veth_host', 'veth_ifindex' or None if not available
    """
    try:
        container.reload()
        
        networks = container.attrs.get('NetworkSettings', {}).get('Networks', {})
        
        if network not in networks:
            logger.debug(f"Container {container.short_id} not in network {network}")
            return None
        
        net_info = networks[network]
        ip_address = net_info.get('IPAddress')
        
        if not ip_address:
            logger.debug(f"Container {container.short_id} has no IP address")
            return None
        
        # Get veth interface info
        pid = container.attrs.get('State', {}).get('Pid')
        veth_host, veth_ifindex = None, None
        
        if pid:
            veth_host, veth_ifindex = find_veth_pair(pid, container.id)
        
        if not veth_ifindex:
            logger.warning(f"Could not find veth interface for container {container.short_id}")
            return None
        
        return {
            'id': container.short_id,
            'name': container.name,
            'ip': ip_address,
            'veth_host': veth_host,
            'veth_ifindex': veth_ifindex,
        }
        
    except Exception as e:
        logger.error(f"Error getting container info: {e}")
        return None


def run_loader(cmd: list) -> bool:
    """Run loader command."""
    try:
        result = subprocess.run([LOADER_PATH] + cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"Loader failed: {result.stderr}")
            return False
        return True
    except Exception as e:
        logger.error(f"Error running loader: {e}")
        return False


def handle_container_start(container: Container, network: str):
    """Handle container start event."""
    logger.info(f"Container started: {container.short_id} ({container.name})")
    
    # Wait for network to be ready
    time.sleep(0.5)
    
    info = get_container_info(container, network)
    if not info:
        return
    
    container_cache[container.id] = info
    
    # Attach TC BPF and add to map
    run_loader(['attach', info['veth_host']])
    run_loader(['add', info['ip'], info['veth_host']])
    
    logger.info(f"Accelerated: {info['name']} ({info['ip']}) via {info['veth_host']}")


def handle_container_stop(container_id: str):
    """Handle container stop event."""
    logger.info(f"Container stopped: {container_id[:12]}")
    
    info = container_cache.pop(container_id, None)
    if not info:
        return
    
    run_loader(['del', info['ip']])
    run_loader(['detach', info['veth_host']])
    
    logger.info(f"Cleaned up: {info['name']}")


def scan_existing_containers(client: docker.DockerClient, network: str):
    """Scan and register existing running containers."""
    logger.info("Scanning existing containers...")
    
    for container in client.containers.list(filters={'status': 'running'}):
        info = get_container_info(container, network)
        if info:
            container_cache[container.id] = info
            run_loader(['attach', info['veth_host']])
            run_loader(['add', info['ip'], info['veth_host']])
            logger.info(f"Registered: {info['name']} ({info['ip']})")


def cleanup_all():
    """Clean up all registered containers."""
    logger.info("Cleaning up...")
    for info in container_cache.values():
        run_loader(['del', info['ip']])
        run_loader(['detach', info['veth_host']])
    container_cache.clear()


def main():
    parser = argparse.ArgumentParser(description='Docker Container Network Manager')
    parser.add_argument('--network', default='bridge', 
                        help='Docker network to monitor (default: bridge)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if os.geteuid() != 0:
        logger.error("This script must be run as root")
        sys.exit(1)
    
    if not os.path.exists(LOADER_PATH):
        logger.error(f"Loader not found: {LOADER_PATH}")
        sys.exit(1)
    
    # Connect to Docker
    try:
        client = docker.from_env()
        client.ping()
    except Exception as e:
        logger.error(f"Failed to connect to Docker: {e}")
        sys.exit(1)
    
    logger.info(f"Monitoring network: {args.network}")
    
    # Signal handlers
    def signal_handler(sig, frame):
        cleanup_all()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Scan existing containers
    scan_existing_containers(client, args.network)
    
    # Monitor Docker events
    logger.info("Monitoring Docker events... (Ctrl+C to stop)")
    
    try:
        for event in client.events(decode=True):
            if event.get('Type') != 'container':
                continue
            
            action = event.get('Action', '')
            container_id = event.get('id', '')
            
            if action == 'start':
                try:
                    container = client.containers.get(container_id)
                    handle_container_start(container, args.network)
                except docker.errors.NotFound:
                    pass
            elif action in ('stop', 'die', 'kill'):
                handle_container_stop(container_id)
    
    except KeyboardInterrupt:
        pass
    finally:
        cleanup_all()


if __name__ == '__main__':
    main()
