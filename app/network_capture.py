import asyncio
import threading
import time
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime
import json
import struct
from collections import deque, defaultdict
import socket
import psutil
import netifaces

# Network capture libraries
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Install with: pip install scapy")

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    print("Warning: PyShark not available. Install with: pip install pyshark")

from .database import get_db, NetworkTraffic
from .config import settings
from .monitoring import logger


class NetworkPacket:
    
    def __init__(self, raw_packet=None, packet_data=None):
        self.timestamp = datetime.utcnow()
        self.source_ip = None
        self.destination_ip = None
        self.source_port = None
        self.destination_port = None
        self.protocol = None
        self.packet_size = 0
        self.flags = None
        self.ttl = None
        self.window_size = None
        self.payload_size = 0
        self.raw_data = None
        
        if raw_packet:
            self._extract_from_raw_packet(raw_packet)
        elif packet_data:
            self._extract_from_packet_data(packet_data)
    
    def _extract_from_raw_packet(self, packet):
        try:
            if IP in packet:
                self.source_ip = packet[IP].src
                self.destination_ip = packet[IP].dst
                self.ttl = packet[IP].ttl
                self.protocol = packet[IP].proto
                self.packet_size = len(packet)
                if TCP in packet:
                    self.source_port = packet[TCP].sport
                    self.destination_port = packet[TCP].dport
                    self.flags = str(packet[TCP].flags)
                    self.window_size = packet[TCP].window
                    self.payload_size = len(packet[TCP].payload)
                
                elif UDP in packet:
                    self.source_port = packet[UDP].sport
                    self.destination_port = packet[UDP].dport
                    self.payload_size = len(packet[UDP].payload)
            
                elif ICMP in packet:
                    self.protocol = "ICMP"
                    self.flags = str(packet[ICMP].type)
            
            elif ARP in packet:
                self.protocol = "ARP"
                self.source_ip = packet[ARP].psrc
                self.destination_ip = packet[ARP].pdst
            
            self.raw_data = bytes(packet)[:1000].hex()
            
        except Exception as e:
            logger.error(f"Error extracting packet features: {e}")
    
    def _extract_from_packet_data(self, packet_data):
        self.source_ip = packet_data.get('source_ip')
        self.destination_ip = packet_data.get('destination_ip')
        self.source_port = packet_data.get('source_port')
        self.destination_port = packet_data.get('destination_port')
        self.protocol = packet_data.get('protocol')
        self.packet_size = packet_data.get('packet_size', 0)
        self.flags = packet_data.get('flags')
        self.ttl = packet_data.get('ttl')
        self.window_size = packet_data.get('window_size')
        self.payload_size = packet_data.get('payload_size', 0)
        self.raw_data = packet_data.get('raw_data')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'packet_size': self.packet_size,
            'flags': self.flags,
            'ttl': self.ttl,
            'window_size': self.window_size,
            'payload_size': self.payload_size,
            'raw_data': self.raw_data
        }
    
    def to_network_traffic_model(self) -> NetworkTraffic:
        return NetworkTraffic(
            timestamp=self.timestamp,
            source_ip=self.source_ip or "0.0.0.0",
            destination_ip=self.destination_ip or "0.0.0.0",
            source_port=self.source_port or 0,
            destination_port=self.destination_port or 0,
            protocol=self.protocol or "UNKNOWN",
            packet_count=1,
            byte_count=self.packet_size,
            duration=0.0,
            flags=self.flags or "",
            raw_data=json.dumps(self.to_dict())
        )


class NetworkCaptureService:
    
    def __init__(self):
        self.is_capturing = False
        self.capture_thread = None
        self.packet_queue = deque(maxlen=10000)
        self.statistics = defaultdict(int)
        self.callbacks = []
        self.interface = None
        self.filter = None
        self.max_packets = 1000000  # 1M packets limit
        
        self.packets_captured = 0
        self.packets_processed = 0
        self.start_time = None
        
        self.available_interfaces = self._get_available_interfaces()
    
    def _get_available_interfaces(self) -> List[Dict[str, str]]:
        interfaces = []
        try:
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    interfaces.append({
                        'name': interface,
                        'ip': ip_info.get('addr', ''),
                        'netmask': ip_info.get('netmask', ''),
                        'status': 'up' if interface in netifaces.interfaces() else 'down'
                    })
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
        
        return interfaces
    
    def add_callback(self, callback: Callable[[NetworkPacket], None]):
        self.callbacks.append(callback)
    
    def remove_callback(self, callback: Callable[[NetworkPacket], None]):
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    def start_capture(self, interface: str = None, filter: str = None, max_packets: int = None):
        if self.is_capturing:
            logger.warning("Network capture already running")
            return False
        
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available. Cannot start capture.")
            return False
        
        self.interface = interface or self._get_default_interface()
        self.filter = filter
        self.max_packets = max_packets or self.max_packets
        self.start_time = datetime.utcnow()
        self.packets_captured = 0
        self.packets_processed = 0
        
        logger.info(f"Starting network capture on interface: {self.interface}")
        
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            daemon=True
        )
        self.capture_thread.start()
        
        self.is_capturing = True
        return True
    
    def stop_capture(self):
        if not self.is_capturing:
            return
        
        logger.info("Stopping network capture")
        self.is_capturing = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        
        self._process_queued_packets()
        
        logger.info(f"Capture stopped. Total packets: {self.packets_captured}")
    
    def _get_default_interface(self) -> str:
        
        try:
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                return gateways['default'][netifaces.AF_INET][1]
            
            if self.available_interfaces:
                return self.available_interfaces[0]['name']
            
            return "eth0"  
        except Exception as e:
            logger.error(f"Error getting default interface: {e}")
            return "eth0"
    
    def _capture_packets(self):
        try:
            def packet_handler(packet):
                if not self.is_capturing:
                    return
                
                self.packets_captured += 1
                
                network_packet = NetworkPacket(raw_packet=packet)
                
                self.packet_queue.append(network_packet)
                
                self.statistics[network_packet.protocol] += 1
                
                if len(self.packet_queue) > 1000:
                    self._process_queued_packets()
                
               
                if self.packets_captured >= self.max_packets:
                    self.stop_capture()
            
            sniff(
                iface=self.interface,
                filter=self.filter,
                prn=packet_handler,
                store=0,  
                stop_filter=lambda p: not self.is_capturing
            )
            
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            self.is_capturing = False
    
    def _process_queued_packets(self):
        while self.packet_queue:
            packet = self.packet_queue.popleft()
            self.packets_processed += 1
            
            # Call all registered callbacks
            for callback in self.callbacks:
                try:
                    callback(packet)
                except Exception as e:
                    logger.error(f"Error in packet callback: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        uptime = (datetime.utcnow() - self.start_time).total_seconds() if self.start_time else 0
        
        return {
            'is_capturing': self.is_capturing,
            'interface': self.interface,
            'filter': self.filter,
            'packets_captured': self.packets_captured,
            'packets_processed': self.packets_processed,
            'queue_size': len(self.packet_queue),
            'uptime_seconds': uptime,
            'packets_per_second': self.packets_captured / max(uptime, 1),
            'protocol_statistics': dict(self.statistics),
            'available_interfaces': self.available_interfaces
        }
    
    def get_network_info(self) -> Dict[str, Any]:
        try:
            
            connections = psutil.net_connections()
            
            
            net_io = psutil.net_io_counters()
            
            addresses = {}
            for interface in self.available_interfaces:
                addresses[interface['name']] = {
                    'ip': interface['ip'],
                    'netmask': interface['netmask'],
                    'status': interface['status']
                }
            
            return {
                'connections': len(connections),
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'interfaces': addresses
            }
        except Exception as e:
            logger.error(f"Error getting network info: {e}")
            return {}


class PySharkCaptureService:
    
    def __init__(self):
        self.is_capturing = False
        self.capture = None
        self.callbacks = []
        self.interface = None
        self.filter = None
    
    def start_capture(self, interface: str = None, filter: str = None):
        if not PYSHARK_AVAILABLE:
            logger.error("PyShark not available")
            return False
        
        if self.is_capturing:
            return False
        
        self.interface = interface or "eth0"
        self.filter = filter
        
        try:
            self.capture = pyshark.LiveCapture(
                interface=self.interface,
                output_file=None,
                bpf_filter=self.filter
            )
            
            threading.Thread(
                target=self._capture_packets,
                daemon=True
            ).start()
            
            self.is_capturing = True
            logger.info(f"PyShark capture started on {self.interface}")
            return True
            
        except Exception as e:
            logger.error(f"Error starting PyShark capture: {e}")
            return False
    
    def stop_capture(self):
        if self.capture:
            self.capture.close()
        self.is_capturing = False
    
    def _capture_packets(self):
        try:
            for packet in self.capture.sniff_continuously():
                if not self.is_capturing:
                    break
                
                network_packet = self._convert_pyshark_packet(packet)
                
                for callback in self.callbacks:
                    try:
                        callback(network_packet)
                    except Exception as e:
                        logger.error(f"Error in PyShark callback: {e}")
                        
        except Exception as e:
            logger.error(f"Error in PyShark capture: {e}")
    
    def _convert_pyshark_packet(self, pyshark_packet) -> NetworkPacket:
        packet_data = {
            'source_ip': None,
            'destination_ip': None,
            'source_port': None,
            'destination_port': None,
            'protocol': None,
            'packet_size': int(pyshark_packet.length) if hasattr(pyshark_packet, 'length') else 0,
            'flags': None,
            'ttl': None,
            'window_size': None,
            'payload_size': 0,
            'raw_data': None
        }
        
        if hasattr(pyshark_packet, 'ip'):
            packet_data['source_ip'] = pyshark_packet.ip.src
            packet_data['destination_ip'] = pyshark_packet.ip.dst
            packet_data['ttl'] = int(pyshark_packet.ip.ttl) if hasattr(pyshark_packet.ip, 'ttl') else None
        
        if hasattr(pyshark_packet, 'tcp'):
            packet_data['protocol'] = 'TCP'
            packet_data['source_port'] = int(pyshark_packet.tcp.srcport)
            packet_data['destination_port'] = int(pyshark_packet.tcp.dstport)
            packet_data['flags'] = pyshark_packet.tcp.flags if hasattr(pyshark_packet.tcp, 'flags') else None
            packet_data['window_size'] = int(pyshark_packet.tcp.window_size) if hasattr(pyshark_packet.tcp, 'window_size') else None
        
       
        elif hasattr(pyshark_packet, 'udp'):
            packet_data['protocol'] = 'UDP'
            packet_data['source_port'] = int(pyshark_packet.udp.srcport)
            packet_data['destination_port'] = int(pyshark_packet.udp.dstport)
        
        
        elif hasattr(pyshark_packet, 'icmp'):
            packet_data['protocol'] = 'ICMP'
            packet_data['flags'] = pyshark_packet.icmp.type if hasattr(pyshark_packet.icmp, 'type') else None
        
        return NetworkPacket(packet_data=packet_data)
    
    def add_callback(self, callback: Callable[[NetworkPacket], None]):
        
        self.callbacks.append(callback)


network_capture_service = NetworkCaptureService()
pyshark_capture_service = PySharkCaptureService()


def get_network_capture_service() -> NetworkCaptureService:
    return network_capture_service


def get_pyshark_capture_service() -> PySharkCaptureService:
    return pyshark_capture_service 