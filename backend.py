import asyncio
import threading
import time
from collections import deque, defaultdict
from typing import List, Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, rdpcap



# --- Data Models for API responses ---

class PacketSummary(BaseModel):
    num: int
    time: str
    src: str
    dst: str
    protocol: str
    length: int
    info: str

class NetworkData(BaseModel):
    pps_data: List[float]
    top_ips_data: Dict[str, List[float]]
    x_axis: List[int]

class AddressTypeDistributionData(BaseModel):
    distribution: Dict[str, int]

class PacketSizeDistributionData(BaseModel):
    distribution: Dict[str, int]

class DNSQPSData(BaseModel):
    dns_qps: List[float]
    x_axis: List[int]

# --- 1. Packet Capture Thread (from network_monitor.py) ---
class PacketCaptureThread(threading.Thread):
    def __init__(self, packet_queue, interface="eth0"):
        super().__init__()
        self.packet_queue = packet_queue
        self.interface = interface
        self.stop_event = threading.Event()
        self.daemon = True

    def run(self):
        print(f"[*] Starting packet capture on interface: {self.interface}")
        try:
            sniff(iface=self.interface, prn=self.process_packet, stop_filter=self.should_stop, store=0)
        except Exception as e:
            print(f"Error during packet capture: {e}")
        print("[*] Packet capture stopped.")

    def process_packet(self, packet):
        if not self.stop_event.is_set():
            self.packet_queue.append(packet)

    def should_stop(self, packet):
        return self.stop_event.is_set()

    def stop(self):
        self.stop_event.set()

# --- 2. Packet Data Processor (from network_monitor.py, slightly modified for backend) ---
class PacketDataProcessor:
    def __init__(self, display_history_len=60, max_packet_list_size=1000):
        self.packet_queue = deque(maxlen=2000)
        self.pps_history = deque(maxlen=display_history_len)
        self.ip_pps_history = defaultdict(lambda: deque(maxlen=display_history_len))
        self.last_update_time = time.time()
        self.display_history_len = display_history_len
        self.packet_list = deque(maxlen=max_packet_list_size)
        self.packet_counter = 0
        self.current_interval_packet_count = 0
        self.current_interval_ip_counts = defaultdict(int)
        self.current_interval_protocol_counts = defaultdict(int)
        self.current_interval_dns_queries = 0

        # Data for new graphs
        self.address_type_counts = defaultdict(int)  # For Unicast vs. Broadcast/Multicast
        self.packet_size_dist = defaultdict(int)  # For Packet Size Distribution
        self.dns_qps_history = deque(maxlen=display_history_len)  # For DNS QPS

    def _reset_current_interval_data(self):
        self.current_interval_packet_count = 0
        self.current_interval_ip_counts.clear()
        self.current_interval_protocol_counts.clear()
        self.current_interval_dns_queries = 0

    def _aggregate_packet(self, packet):
        self.current_interval_packet_count += 1
        src_ip, dst_ip = None, None
        length = len(packet)

        # Graph 6: Unicast vs. Broadcast/Multicast
        if Ether in packet:
            if packet[Ether].dst == "ff:ff:ff:ff:ff:ff":
                self.address_type_counts['Broadcast'] += 1
            elif packet[Ether].dst.startswith("01:00:5e") or packet[Ether].dst.startswith("33:33"):
                self.address_type_counts['Multicast'] += 1
            else:
                self.address_type_counts['Unicast'] += 1

        # Graph 7: Packet Size Distribution
        size_bins = [(64, "0-64"), (256, "64-256"), (512, "256-512"), 
                     (1024, "512-1024"), (1518, "1024-1518"), (float('inf'), ">1518")]
        for size_limit, label in size_bins:
            if length <= size_limit:
                self.packet_size_dist[label] += 1
                break

        if IP in packet:
            src_ip, dst_ip = packet[IP].src, packet[IP].dst
            proto = "Other"
            if TCP in packet: 
                proto = "TCP"
            elif UDP in packet: 
                proto = "UDP"
                # Graph 8: DNS Queries per Second
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    self.current_interval_dns_queries += 1
            elif ICMP in packet: 
                proto = "ICMP"
            else: 
                proto = "IP"
        elif Ether in packet:
            proto, src_ip, dst_ip = "Ethernet", packet[Ether].src, packet[Ether].dst
        else:
            proto = "Other"
        
        self.current_interval_protocol_counts[proto] += 1
        if src_ip: self.current_interval_ip_counts[src_ip] += 1
        if dst_ip and dst_ip != src_ip: self.current_interval_ip_counts[dst_ip] += 1

    def _parse_packet_summary(self, packet) -> PacketSummary:
        self.packet_counter += 1
        timestamp = time.strftime("%H:%M:%S", time.localtime(float(packet.time)))
        src_ip, dst_ip, protocol, info = "N/A", "N/A", "N/A", packet.summary()
        length = len(packet)
        if IP in packet:
            src_ip, dst_ip = packet[IP].src, packet[IP].dst
            if TCP in packet: protocol = "TCP"
            elif UDP in packet: protocol = "UDP"
            elif ICMP in packet: protocol = "ICMP"
            else: protocol = "IP"
        elif Ether in packet:
            protocol, src_ip, dst_ip = "Ethernet", packet[Ether].src, packet[Ether].dst
        return PacketSummary(num=self.packet_counter, time=timestamp, src=src_ip, dst=dst_ip, protocol=protocol, length=length, info=info)

    def process_live_packets(self):
        current_time = time.time()
        elapsed_time = current_time - self.last_update_time
        if elapsed_time >= 1.0:
            packets_in_interval = 0
            while self.packet_queue:
                packet = self.packet_queue.popleft()
                self._aggregate_packet(packet)
                self.packet_list.append(self._parse_packet_summary(packet))
                packets_in_interval += 1
            
            current_pps = packets_in_interval / elapsed_time if elapsed_time > 0 else 0
            self.pps_history.append(current_pps)

            # Calculate and store DNS QPS
            current_dns_qps = self.current_interval_dns_queries / elapsed_time if elapsed_time > 0 else 0
            self.dns_qps_history.append(current_dns_qps)

            active_ips_in_interval = set(self.current_interval_ip_counts.keys())
            for ip, count in self.current_interval_ip_counts.items():
                self.ip_pps_history[ip].append(count / elapsed_time if elapsed_time > 0 else 0)
            
            all_tracked_ips = set(self.ip_pps_history.keys())
            ips_to_pad = all_tracked_ips - active_ips_in_interval
            for ip in ips_to_pad:
                self.ip_pps_history[ip].append(0)

            self._reset_current_interval_data()
            self.last_update_time = current_time
            return True
        return False

    def get_pps_data(self):
        return list(self.pps_history)

    def get_top_ips_pps_data(self, num_ips=5):
        ip_total_pps = {ip: sum(pps_deque) for ip, pps_deque in self.ip_pps_history.items()}
        sorted_ips = sorted(ip_total_pps.items(), key=lambda item: item[1], reverse=True)
        top_ips = [ip for ip, _ in sorted_ips[:num_ips]]
        
        top_ips_data = {}
        expected_len = len(self.pps_history)
        for ip in top_ips:
            ip_data = list(self.ip_pps_history[ip])
            # Pad if data is shorter than expected
            if len(ip_data) < expected_len:
                padded_data = [0.0] * (expected_len - len(ip_data)) + ip_data
                top_ips_data[ip] = padded_data
            else:
                top_ips_data[ip] = ip_data
        return top_ips_data

    def get_packet_list_data(self) -> List[PacketSummary]:
        return list(self.packet_list)

    def get_address_type_distribution(self) -> Dict[str, int]:
        return dict(self.address_type_counts)

    def get_packet_size_distribution(self) -> Dict[str, int]:
        return dict(self.packet_size_dist)

    def get_dns_qps_data(self) -> List[float]:
        return list(self.dns_qps_history)

    def reset_data(self):
        self.packet_queue.clear()
        self.pps_history.clear()
        self.ip_pps_history.clear()
        self.packet_list.clear()
        self.packet_counter = 0
        self._reset_current_interval_data()
        self.last_update_time = time.time()
        # Reset new graph data
        self.address_type_counts.clear()
        self.packet_size_dist.clear()
        self.dns_qps_history.clear()

# --- 3. Backend Service ---
class NetworkMonitorService:
    def __init__(self):
        self.data_processor = PacketDataProcessor(display_history_len=60, max_packet_list_size=1000)
        self.capture_thread: PacketCaptureThread = None
        self.processing_thread: threading.Thread = None
        self.stop_processing = threading.Event()
        self.is_capturing = False
        self.lock = threading.Lock()

    def _processing_loop(self):
        while not self.stop_processing.is_set():
            with self.lock:
                self.data_processor.process_live_packets()
            time.sleep(1)

    def start_capture(self, interface: str):
        if self.is_capturing:
            raise HTTPException(status_code=400, detail="Capture is already running.")
        
        with self.lock:
            self.data_processor.reset_data()
        
        self.capture_thread = PacketCaptureThread(self.data_processor.packet_queue, interface=interface)
        self.capture_thread.start()

        self.stop_processing.clear()
        self.processing_thread = threading.Thread(target=self._processing_loop)
        self.processing_thread.daemon = True
        self.processing_thread.start()
        
        self.is_capturing = True
        return {"message": f"Packet capture started on interface {interface}"}

    def stop_capture(self):
        if not self.is_capturing:
            raise HTTPException(status_code=400, detail="Capture is not running.")
        
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread.join(timeout=2)
        
        self.stop_processing.set()
        if self.processing_thread:
            self.processing_thread.join(timeout=2)

        self.is_capturing = False
        return {"message": "Packet capture stopped."}

    def get_network_data(self) -> NetworkData:
        with self.lock:
            pps_data = self.data_processor.get_pps_data()
            top_ips_data = self.data_processor.get_top_ips_pps_data()
            # For live data, the x-axis represents "seconds ago"
            x_axis = list(range(-len(pps_data) + 1, 1))
            return NetworkData(pps_data=pps_data, top_ips_data=top_ips_data, x_axis=x_axis)

    def get_address_type_distribution_data(self) -> AddressTypeDistributionData:
        with self.lock:
            distribution = self.data_processor.get_address_type_distribution()
            return AddressTypeDistributionData(distribution=distribution)

    def get_packet_size_distribution_data(self) -> PacketSizeDistributionData:
        with self.lock:
            distribution = self.data_processor.get_packet_size_distribution()
            return PacketSizeDistributionData(distribution=distribution)

    def get_dns_qps_data(self) -> DNSQPSData:
        with self.lock:
            dns_qps = self.data_processor.get_dns_qps_data()
            x_axis = list(range(-len(dns_qps) + 1, 1))
            return DNSQPSData(dns_qps=dns_qps, x_axis=x_axis)

    def get_packets(self, limit: int = 100) -> List[PacketSummary]:
        with self.lock:
            packets = self.data_processor.get_packet_list_data()
            return packets[-limit:]

# --- 4. FastAPI Application ---
app = FastAPI(
    title="Network Packet Monitor API",
    description="An API to capture and analyze network packets in real-time.",
    version="1.0.0"
)

# Add CORS middleware to allow all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Create a singleton instance of the service
monitor_service = NetworkMonitorService()

@app.on_event("shutdown")
def shutdown_event():
    print("Server is shutting down. Stopping capture...")

class StartCaptureRequest(BaseModel):
    interface: str = "en0" # Default to a common macOS interface name

@app.post("/capture/start", tags=["Capture Control"])
def start_capture(request: StartCaptureRequest):
    """
    Starts the network packet capture on a specified interface.
    """
    try:
        return monitor_service.start_capture(request.interface)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/capture/stop", tags=["Capture Control"])
def stop_capture():
    """
    Stops the current network packet capture.
    """
    return monitor_service.stop_capture()

@app.get("/capture/status", tags=["Capture Control"])
def get_status():
    """
    Returns the current capture status.
    """
    return {"is_capturing": monitor_service.is_capturing}

@app.get("/data", response_model=NetworkData, tags=["Data"])
def get_data():
    """
    Provides the latest aggregated network data, including total PPS and PPS for top IPs.
    The x-axis represents time as 'seconds ago' from the current moment.
    """
    return monitor_service.get_network_data()

@app.get("/data/address_type_distribution", response_model=AddressTypeDistributionData, tags=["Data"])
def get_address_type_distribution():
    """
    Provides the distribution of Unicast vs. Broadcast/Multicast packets.
    """
    return monitor_service.get_address_type_distribution_data()

@app.get("/data/packet_size_distribution", response_model=PacketSizeDistributionData, tags=["Data"])
def get_packet_size_distribution():
    """
    Provides the distribution of packet sizes.
    """
    return monitor_service.get_packet_size_distribution_data()

@app.get("/data/dns_qps", response_model=DNSQPSData, tags=["Data"])
def get_dns_qps():
    """
    Provides the DNS queries per second over time.
    """
    return monitor_service.get_dns_qps_data()

@app.get("/packets", response_model=List[PacketSummary], tags=["Data"])
def get_packets(limit: int = 100):
    """
    Provides a list of the most recently captured packets.
    """
    return monitor_service.get_packets(limit)

# To run this backend server:
# 1. Make sure you have installed the required packages:
#    pip install fastapi uvicorn python-multipart scapy
# 2. Save this file as backend.py
# 3. Run the server from your terminal:
#    uvicorn backend:app --reload
#
# You can then access the API documentation at http://127.0.0.1:8000/docs