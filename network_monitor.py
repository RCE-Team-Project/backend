
import sys
import threading
import time
from collections import deque, defaultdict
from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, Ether # Scapy 사용
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel, QPushButton, QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView
from PyQt5.QtCore import QTimer, QThread, pyqtSignal, Qt
import pyqtgraph as pg
import random # IP별 색상 구분을 위해 사용
import numpy as np # numpy 추가

# --- 1. Packet Capture Thread (기존과 동일) ---
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
            # store=0으로 설정하여 Scapy가 패킷을 내부적으로 저장하지 않도록 함 (메모리 절약)
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

# --- 2. Packet Data Processor (수정됨) ---
class PacketDataProcessor:
    # display_history_len: 라이브 캡처 시 화면에 표시할 과거 데이터 길이 (초 단위)
    # max_packet_list_size: 패킷 리스트의 최대 크기 (None이면 무제한, 메모리 주의!)
    def __init__(self, display_history_len=60, max_packet_list_size=None):
        self.packet_queue = deque(maxlen=2000)
        
        self.pps_history = deque() # maxlen 없이 초기화 (라이브/PCAP 모두 사용)
        self.ip_pps_history = defaultdict(deque) # maxlen 없이 초기화

        self.last_update_time = time.time()
        self.display_history_len = display_history_len # 라이브 캡처 시에만 사용

        self.packet_list = deque(maxlen=max_packet_list_size) 
        self.packet_counter = 0

        self.current_interval_packet_count = 0
        self.current_interval_ip_counts = defaultdict(int) 
        self.current_interval_protocol_counts = defaultdict(int)

    def _reset_current_interval_data(self):
        self.current_interval_packet_count = 0
        self.current_interval_ip_counts.clear()
        self.current_interval_protocol_counts.clear()

    def _aggregate_packet(self, packet):
        self.current_interval_packet_count += 1
        
        src_ip = None
        dst_ip = None

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if TCP in packet:
                proto = "TCP"
            elif UDP in packet:
                proto = "UDP"
            elif ICMP in packet:
                proto = "ICMP"
            else:
                proto = "IP"
        elif Ether in packet:
            proto = "Ethernet"
            src_ip = packet[Ether].src # MAC 주소
            dst_ip = packet[Ether].dst # MAC 주소
        else:
            proto = "Other"
        
        self.current_interval_protocol_counts[proto] += 1

        # IP별 패킷 카운트
        if src_ip: # IP가 존재할 경우에만 카운트
            self.current_interval_ip_counts[src_ip] += 1
        if dst_ip and dst_ip != src_ip: # 출발지와 목적지가 다를 경우만 목적지 IP도 카운트
            self.current_interval_ip_counts[dst_ip] += 1


    def _parse_packet_summary(self, packet):
        # 패킷 요약 정보 추출
        self.packet_counter += 1
        packet_num = self.packet_counter
        # TypeError 해결: packet.time을 float으로 명시적 변환
        timestamp = time.strftime("%H:%M:%S", time.localtime(float(packet.time)))
        
        src_ip = "N/A"
        dst_ip = "N/A"
        protocol = "N/A"
        length = len(packet)
        info = packet.summary()

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            elif ICMP in packet:
                protocol = "ICMP"
            else:
                protocol = "IP"
        elif Ether in packet:
            protocol = "Ethernet"
            src_ip = packet[Ether].src # MAC 주소
            dst_ip = packet[Ether].dst # MAC 주소

        return {
            "num": packet_num,
            "time": timestamp,
            "src": src_ip,
            "dst": dst_ip,
            "protocol": protocol,
            "length": length,
            "info": info
        }

    def process_live_packets(self):
        current_time = time.time()
        elapsed_time = current_time - self.last_update_time

        # 1초마다 집계 및 업데이트
        if elapsed_time >= 1.0:
            packets_in_interval = 0
            while self.packet_queue: # 큐에서 지난 1초간의 패킷을 모두 처리
                packet = self.packet_queue.popleft()
                self._aggregate_packet(packet) # PPS 및 프로토콜 집계
                self.packet_list.append(self._parse_packet_summary(packet)) # 리스트용 패킷 정보 저장
                packets_in_interval += 1

            # PPS 계산
            current_pps = packets_in_interval / elapsed_time if elapsed_time > 0 else 0
            self.pps_history.append(current_pps)
            # 라이브 캡처 시에만 display_history_len으로 길이 제한
            if len(self.pps_history) > self.display_history_len:
                self.pps_history.popleft()

            # IP별 PPS 업데이트
            for ip, count in self.current_interval_ip_counts.items():
                self.ip_pps_history[ip].append(count / elapsed_time if elapsed_time > 0 else 0)
                # 라이브 캡처 시에만 display_history_len으로 길이 제한
                if len(self.ip_pps_history[ip]) > self.display_history_len:
                    self.ip_pps_history[ip].popleft()
            # 현재 인터벌에 패킷이 없었던 IP는 0으로 채움
            for ip in list(self.ip_pps_history.keys()):
                if ip not in self.current_interval_ip_counts: # 현재 인터벌에 없던 IP는 0으로 채움
                    self.ip_pps_history[ip].append(0)
                    if len(self.ip_pps_history[ip]) > self.display_history_len:
                        self.ip_pps_history[ip].popleft()

            self._reset_current_interval_data()
            self.last_update_time = current_time
            print(f"[DEBUG] Live PPS: {current_pps}, Packets in interval: {packets_in_interval}, Queue size: {len(self.packet_queue)}") # 디버그 출력
            return True # 데이터가 업데이트되었음을 알림
        return False

    def process_pcap_file(self, pcap_file_path):
        print(f"[*] Processing PCAP file: {pcap_file_path}")
        self.pps_history.clear()
        self.ip_pps_history.clear() # IP별 PPS 초기화
        self.packet_list.clear() # 기존 리스트 초기화
        self.packet_counter = 0
        self._reset_current_interval_data()

        try:
            packets = rdpcap(pcap_file_path)
        except Exception as e:
            print(f"Error reading PCAP file: {e}")
            return False

        if not packets:
            print("No packets found in PCAP file.")
            return False

        start_time = packets[0].time
        current_interval_start_time = start_time

        for packet in packets:
            # 현재 패킷이 다음 1초 구간으로 넘어갔는지 확인
            if packet.time >= current_interval_start_time + 1.0:
                current_pps = self.current_interval_packet_count / (packet.time - current_interval_start_time) if (packet.time - current_interval_start_time) > 0 else 0
                self.pps_history.append(current_pps)

                # IP별 PPS 업데이트
                for ip, count in self.current_interval_ip_counts.items():
                    self.ip_pps_history[ip].append(count / (packet.time - current_interval_start_time) if (packet.time - current_interval_start_time) > 0 else 0)
                for ip in list(self.ip_pps_history.keys()):
                    if ip not in self.current_interval_ip_counts: # 현재 인터벌에 없던 IP는 0으로 채움
                        self.ip_pps_history[ip].append(0)

                self._reset_current_interval_data()
                current_interval_start_time = packet.time

            self._aggregate_packet(packet) # 현재 패킷 집계
            self.packet_list.append(self._parse_packet_summary(packet)) # 리스트용 패킷 정보 저장

        # 마지막 구간 데이터 처리
        if self.current_interval_packet_count > 0:
            current_pps = self.current_interval_packet_count / (packet.time - current_interval_start_time) if (packet.time - current_interval_start_time) > 0 else 0
            self.pps_history.append(current_pps)
            # 마지막 IP별 PPS 업데이트
            for ip, count in self.current_interval_ip_counts.items():
                self.ip_pps_history[ip].append(count / (packet.time - current_interval_start_time) if (packet.time - current_interval_start_time) > 0 else 0)
            for ip in list(self.ip_pps_history.keys()):
                if ip not in self.current_interval_ip_counts: # 현재 인터벌에 없던 IP는 0으로 채움
                    self.ip_pps_history[ip].append(0)
        
        print(f"[*] PCAP file processing complete. Total intervals: {len(self.pps_history)}")
        return True

    def get_pps_data(self):
        return list(self.pps_history)

    def get_top_ips_pps_data(self, num_ips=5):
        # 각 IP의 총 PPS 합계를 기준으로 상위 N개 IP를 찾음
        ip_total_pps = defaultdict(float)
        for ip, pps_deque in self.ip_pps_history.items():
            ip_total_pps[ip] = sum(pps_deque)

        sorted_ips = sorted(ip_total_pps.items(), key=lambda item: item[1], reverse=True)
        top_ips = [ip for ip, _ in sorted_ips[:num_ips]]

        # 상위 IP들의 PPS 데이터 반환
        top_ips_data = {}
        # pps_history의 길이를 기준으로 패딩
        expected_len = len(self.pps_history)
        for ip in top_ips:
            ip_data = list(self.ip_pps_history[ip])
            if len(ip_data) < expected_len:
                # 앞부분에 0을 채워 넣음
                padded_data = [0.0] * (expected_len - len(ip_data)) + ip_data
                top_ips_data[ip] = padded_data
            else:
                top_ips_data[ip] = ip_data
        
        return top_ips_data

    def get_packet_list_data(self):
        return list(self.packet_list)

# --- 3. GUI 및 실시간 그래프 업데이트 (수정됨) ---
class RealtimePacketMonitor(QMainWindow):
    def __init__(self, interface="eth0"):
        super().__init__()
        self.setWindowTitle("Real-time & PCAP Network Packet Monitor")
        self.setGeometry(100, 100, 1400, 900) # 창 크기 확장

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        # --- 컨트롤 버튼 ---
        self.control_layout = QVBoxLayout()
        self.load_pcap_button = QPushButton("Load PCAP File")
        self.load_pcap_button.clicked.connect(self.load_pcap_file)
        self.control_layout.addWidget(self.load_pcap_button)

        self.start_live_capture_button = QPushButton("Start Live Capture")
        self.start_live_capture_button.clicked.connect(self.start_live_capture)
        self.control_layout.addWidget(self.start_live_capture_button)

        self.stop_live_capture_button = QPushButton("Stop Live Capture")
        self.stop_live_capture_button.clicked.connect(self.stop_live_capture)
        self.stop_live_capture_button.setEnabled(False)
        self.control_layout.addWidget(self.stop_live_capture_button)
        
        self.layout.addLayout(self.control_layout)

        # --- 그래프 영역 ---
        self.graph_layout = QVBoxLayout()
        self.pps_plot_widget = pg.PlotWidget()
        self.pps_plot_widget.setTitle("Packets Per Second (PPS) - Total & Top IPs")
        self.pps_plot_widget.setLabel('bottom', "Time (seconds)")
        self.pps_plot_widget.setLabel('left', "PPS")
        self.pps_curve_total = self.pps_plot_widget.plot(pen='y', name='Total PPS') # 전체 PPS
        self.ip_pps_curves = {} # IP별 PPS 커브 저장용 딕셔너리
        self.pps_plot_widget.addLegend() # 범례 추가
        self.graph_layout.addWidget(self.pps_plot_widget)

        self.layout.addLayout(self.graph_layout)

        # --- 패킷 리스트 영역 ---
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7) # Num, Time, Source, Destination, Protocol, Length, Info
        self.packet_table.setHorizontalHeaderLabels(["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents) # 내용에 맞춰 컬럼 너비 자동 조절
        self.packet_table.horizontalHeader().setStretchLastSection(True) # 마지막 컬럼은 남은 공간 채우기
        self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers) # 편집 불가능하게 설정
        self.layout.addWidget(self.packet_table)

        self.data_processor = PacketDataProcessor(display_history_len=60) # max_packet_list_size 기본값 None
        self.interface = interface
        self.packet_capture_thread = None
        self.is_live_capturing = False

        self.timer = QTimer()
        self.timer.setInterval(1000) # 1초마다 업데이트
        self.timer.timeout.connect(self.update_gui)
        self.timer.start()

        self.ip_colors = {} # IP별 색상 저장용

    def get_ip_color(self, ip):
        if ip not in self.ip_colors:
            # 랜덤 색상 생성 (PyQtGraph는 (R,G,B) 튜플 또는 이름 사용)
            # 너무 밝거나 어두운 색은 피하도록 조정 가능
            self.ip_colors[ip] = (random.randint(50, 200), random.randint(50, 200), random.randint(50, 200))
        return self.ip_colors[ip]

    def start_live_capture(self):
        if self.is_live_capturing:
            return

        self.data_processor = PacketDataProcessor(display_history_len=60) # 새 데이터 프로세서 인스턴스 생성
        self.packet_table.setRowCount(0) # 리스트 초기화
        self.pps_plot_widget.clear() # 그래프 초기화
        self.pps_curve_total = self.pps_plot_widget.plot(pen='y', name='Total PPS') # 전체 PPS 다시 추가
        self.ip_pps_curves.clear() # IP별 커브 초기화
        self.pps_plot_widget.addLegend() # 범례 다시 추가

        self.packet_capture_thread = PacketCaptureThread(self.data_processor.packet_queue, interface=self.interface)
        self.packet_capture_thread.start()
        self.is_live_capturing = True
        self.start_live_capture_button.setEnabled(False)
        self.stop_live_capture_button.setEnabled(True)
        self.load_pcap_button.setEnabled(False)
        print("[*] Live capture started.")

    def stop_live_capture(self):
        if not self.is_live_capturing:
            return

        if self.packet_capture_thread:
            self.packet_capture_thread.stop()
            self.packet_capture_thread.join(timeout=5) # 스레드 종료 대기
            if self.packet_capture_thread.is_alive():
                print("[!] Warning: Capture thread did not terminate gracefully.")
            self.packet_capture_thread = None
        self.is_live_capturing = False
        self.start_live_capture_button.setEnabled(True)
        self.stop_live_capture_button.setEnabled(False)
        self.load_pcap_button.setEnabled(True)
        print("[*] Live capture stopped.")

    def load_pcap_file(self):
        self.stop_live_capture() # 라이브 캡처 중이면 중지

        file_dialog = QFileDialog(self)
        file_dialog.setNameFilter("PCAP files (*.pcap *.pcapng)")
        file_dialog.setWindowTitle("Select PCAP File")
        if file_dialog.exec_():
            pcap_file_path = file_dialog.selectedFiles()[0]
            # 새 데이터 프로세서 인스턴스 생성 (PCAP은 display_history_len이 무의미하므로 기본값 사용)
            self.data_processor = PacketDataProcessor(display_history_len=60) 
            
            self.pps_plot_widget.clear() # 그래프 초기화
            self.pps_curve_total = self.pps_plot_widget.plot(pen='y', name='Total PPS') # 전체 PPS 다시 추가
            self.ip_pps_curves.clear() # IP별 커브 초기화
            self.pps_plot_widget.addLegend() # 범례 다시 추가

            if self.data_processor.process_pcap_file(pcap_file_path):
                self.update_gui(is_pcap=True) # PCAP 데이터로 GUI 업데이트
                self.start_live_capture_button.setEnabled(True)
                self.load_pcap_button.setEnabled(True)
            else:
                print("[!] Failed to process PCAP file.")
                self.data_processor = PacketDataProcessor(display_history_len=60) # 실패 시 초기화
                self.update_gui() # 그래프 초기화

    def update_gui(self, is_pcap=False):
        # --- 그래프 데이터 업데이트 ---
        if self.is_live_capturing:
            self.data_processor.process_live_packets()
            pps_data = self.data_processor.get_pps_data()
            x_data = [-i for i in range(len(pps_data) -1, -1, -1)]
            self.pps_plot_widget.setLabel('bottom', "Time (seconds ago)")
            self.pps_plot_widget.setXRange(-self.data_processor.display_history_len, 0)
        elif is_pcap: # PCAP 파일 로드 후 한 번만 호출
            pps_data = self.data_processor.get_pps_data()
            x_data = list(range(len(pps_data)))
            self.pps_plot_widget.setLabel('bottom', "Time (seconds from start)")
            self.pps_plot_widget.setXRange(0, len(pps_data))
        else:
            if not self.data_processor.get_pps_data():
                pps_data = []
                x_data = []
                self.pps_plot_widget.setLabel('bottom', "Time (seconds)")
                self.pps_plot_widget.setXRange(0, self.data_processor.display_history_len)
            else:
                pps_data = self.data_processor.get_pps_data()
                # PCAP 데이터인지 라이브 캡처 데이터인지에 따라 X축 레이블 조정
                # PCAP 데이터는 display_history_len보다 길 수 있음
                if len(pps_data) > self.data_processor.display_history_len and self.data_processor.display_history_len != 0: # PCAP 데이터일 가능성
                    x_data = list(range(len(pps_data)))
                    self.pps_plot_widget.setLabel('bottom', "Time (seconds from start)")
                    self.pps_plot_widget.setXRange(0, len(pps_data))
                else: # 라이브 캡처 중단 후 데이터일 가능성
                    x_data = [-i for i in range(len(pps_data) -1, -1, -1)]
                    self.pps_plot_widget.setLabel('bottom', "Time (seconds ago)")
                    self.pps_plot_widget.setXRange(-self.data_processor.display_history_len, 0)

        # numpy 배열로 변환
        x_data_np = np.array(x_data, dtype=float)
        pps_data_np = np.array(pps_data, dtype=float)

        # 디버그 출력
        print(f"[DEBUG] update_gui - x_data_np: {x_data_np[:5]}..., pps_data_np: {pps_data_np[:5]}...")
        print(f"[DEBUG] update_gui - len(x_data_np): {len(x_data_np)}, len(pps_data_np): {len(pps_data_np)}")

        # 데이터가 비어있지 않을 때만 setData 호출
        if len(x_data_np) > 0 and len(pps_data_np) > 0:
            self.pps_curve_total.setData(x=x_data_np, y=pps_data_np) # 전체 PPS 업데이트
        else:
            self.pps_curve_total.clear() # 데이터가 없으면 그래프 지우기

        # IP별 PPS 그래프 업데이트
        top_ips_data = self.data_processor.get_top_ips_pps_data(num_ips=5)
        
        # 기존 IP별 커브 제거
        # self.ip_pps_curves 딕셔너리에 없는 IP는 제거하지 않도록 수정
        current_ips_on_plot = list(self.ip_pps_curves.keys())
        for ip_on_plot in current_ips_on_plot:
            if ip_on_plot not in top_ips_data: # 현재 상위 IP에 없으면 제거
                self.pps_plot_widget.removeItem(self.ip_pps_curves[ip_on_plot])
                del self.ip_pps_curves[ip_on_plot]

        # 새로운 IP별 커브 추가 또는 업데이트
        for ip, ip_pps_data in top_ips_data.items():
            ip_pps_data_np = np.array(ip_pps_data, dtype=float)
            # x_data의 길이와 ip_pps_data의 길이가 일치하고 비어있지 않을 때만 그리기
            if len(x_data_np) == len(ip_pps_data_np) and len(x_data_np) > 0:
                color = self.get_ip_color(ip)
                # 이미 커브가 있다면 업데이트, 없으면 새로 생성
                if ip not in self.ip_pps_curves:
                    self.ip_pps_curves[ip] = self.pps_plot_widget.plot(pen=pg.mkPen(color=color, width=1), name=f'IP: {ip}')
                self.ip_pps_curves[ip].setData(x=x_data_np, y=ip_pps_data_np)
            else:
                # 데이터가 없거나 길이가 맞지 않으면 해당 IP 커브 제거
                if ip in self.ip_pps_curves:
                    self.pps_plot_widget.removeItem(self.ip_pps_curves[ip])
                    del self.ip_pps_curves[ip]
                print(f"[DEBUG] IP {ip} data issue: x_data_np len={len(x_data_np)}, ip_pps_data_np len={len(ip_pps_data_np)}")


        # --- 패킷 리스트 업데이트 ---
        packet_list_data = self.data_processor.get_packet_list_data()
        
        if is_pcap: # PCAP 파일 로드 시에는 모든 패킷을 한 번에 추가
            self.packet_table.setRowCount(len(packet_list_data))
            for i, pkt in enumerate(packet_list_data):
                self.packet_table.setItem(i, 0, QTableWidgetItem(str(pkt["num"])))
                self.packet_table.setItem(i, 1, QTableWidgetItem(pkt["time"])) 
                self.packet_table.setItem(i, 2, QTableWidgetItem(pkt["src"])) 
                self.packet_table.setItem(i, 3, QTableWidgetItem(pkt["dst"])) 
                self.packet_table.setItem(i, 4, QTableWidgetItem(pkt["protocol"])) 
                self.packet_table.setItem(i, 5, QTableWidgetItem(str(pkt["length"])))
                self.packet_table.setItem(i, 6, QTableWidgetItem(pkt["info"])) 
            self.packet_table.scrollToBottom()
        elif self.is_live_capturing:
            current_table_rows = self.packet_table.rowCount()
            # deque의 maxlen이 None이므로, 오래된 패킷이 제거될 일은 없음.
            # 따라서 단순히 새로운 패킷만 추가하면 됨.
            for i in range(current_table_rows, len(packet_list_data)):
                pkt = packet_list_data[i]
                row_position = self.packet_table.rowCount()
                self.packet_table.insertRow(row_position)
                self.packet_table.setItem(row_position, 0, QTableWidgetItem(str(pkt["num"])))
                self.packet_table.setItem(row_position, 1, QTableWidgetItem(pkt["time"])) 
                self.packet_table.setItem(row_position, 2, QTableWidgetItem(pkt["src"])) 
                self.packet_table.setItem(row_position, 3, QTableWidgetItem(pkt["dst"])) 
                self.packet_table.setItem(row_position, 4, QTableWidgetItem(pkt["protocol"])) 
                self.packet_table.setItem(row_position, 5, QTableWidgetItem(str(pkt["length"])))
                self.packet_table.setItem(row_position, 6, QTableWidgetItem(pkt["info"])) 
            self.packet_table.scrollToBottom()
        else: # 라이브 캡처도 아니고 PCAP도 로드되지 않았을 때 (또는 중단 후)
            # 기존 데이터를 유지하므로, 여기서 데이터를 초기화하지 않음
            # 다만, 데이터가 없는 초기 상태일 경우를 대비하여 빈 리스트로 설정
            if not self.data_processor.get_packet_list_data():
                self.packet_table.setRowCount(0)

    def closeEvent(self, event):
        self.stop_live_capture()
        print("[*] Application closed.")
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    interface_name = "en0" # 여기에 실제 인터페이스 이름을 입력하세요!
    
    monitor = RealtimePacketMonitor(interface=interface_name)
    monitor.show()
    sys.exit(app.exec_())
