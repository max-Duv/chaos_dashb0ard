from PyQt6.QtCore import QSize, Qt, QThread, pyqtSignal, QObject, QTimer
from PyQt6.QtWidgets import QApplication, QMainWindow, QGridLayout, QWidget, QSlider, QLabel, QHBoxLayout, QVBoxLayout, QPushButton, QComboBox
import pyqtgraph as pg
import numpy as np
import time
import signal
import scapy.all as scapy
import dns.resolver

# Defaults
fft_size = 4096
num_rows = 200
center_freq = 750e6
sample_rates = [56, 40, 20, 10, 5, 2, 1, 0.5]
sample_rate = sample_rates[0] * 1e6
time_plot_samples = 500
gain = 50
sdr_type = "sim"

class DNSAnalyzer(QObject):
    dns_query_detected = pyqtSignal(str)
    dns_anomaly_detected = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.resolver = dns.resolver.Resolver()

    def analyze_packet(self, packet):
        if packet.haslayer(scapy.DNS):
            dns_layer = packet.getlayer(scapy.DNS)
            if dns_layer.qr == 0:  # DNS query
                query_name = dns_layer.qd.qname.decode()
                self.dns_query_detected.emit(query_name)
            elif dns_layer.qr == 1:  # DNS response
                # Implement DNS spoofing/poisoning detection logic here
                self.detect_spoofing(dns_layer)

    def detect_spoofing(self, dns_layer):
        # Example logic to detect DNS spoofing
        try:
            query_name = dns_layer.qd.qname.decode()
            response_ips = [dns_layer.an[i].rdata for i in range(dns_layer.ancount)]
            resolved_ips = [str(ip) for ip in self.resolver.resolve(query_name, 'A')]
            if set(response_ips) != set(resolved_ips):
                self.dns_anomaly_detected.emit(f"DNS Spoofing Detected for {query_name}")
        except Exception as e:
            print(f"Error in detecting spoofing: {e}")

    def start_sniffing(self):
        scapy.sniff(filter="udp port 53", prn=self.analyze_packet, store=0)

class SDRWorker(QObject):
    def __init__(self):
        super().__init__()
        self.gain = gain
        self.sample_rate = sample_rate
        self.freq = 0
        self.spectrogram = -50 * np.ones((fft_size, num_rows))
        self.PSD_avg = -50 * np.ones(fft_size)
        self.dns_analyzer = DNSAnalyzer()

        # PyQt Signals
        self.time_plot_update = pyqtSignal(np.ndarray)
        self.freq_plot_update = pyqtSignal(np.ndarray)
        self.waterfall_plot_update = pyqtSignal(np.ndarray)
        self.end_of_run = pyqtSignal()
        self.dns_analyzer.dns_query_detected.connect(self.handle_dns_query)
        self.dns_analyzer.dns_anomaly_detected.connect(self.handle_dns_anomaly)

    def handle_dns_query(self, query_name):
        print(f"DNS Query Detected: {query_name}")

    def handle_dns_anomaly(self, anomaly):
        print(f"DNS Anomaly Detected: {anomaly}")

    def update_freq(self, val):
        print("Updated freq to:", val, 'kHz')
        if sdr_type == "pluto":
            sdr.rx_lo = int(val * 1e3)
        elif sdr_type == "usrp":
            usrp.set_rx_freq(uhd.libpyuhd.types.tune_request(val * 1e3), 0)
        flush_buffer()

    def update_gain(self, val):
        print("Updated gain to:", val, 'dB')
        self.gain = val
        if sdr_type == "pluto":
            sdr.rx_hardwaregain_chan0 = val
        elif sdr_type == "usrp":
            usrp.set_rx_gain(val, 0)
        flush_buffer()

    def update_sample_rate(self, val):
        print("Updated sample rate to:", sample_rates[val], 'MHz')
        if sdr_type == "pluto":
            sdr.sample_rate = int(sample_rates[val] * 1e6)
            sdr.rx_rf_bandwidth = int(sample_rates[val] * 1e6 * 0.8)
        elif sdr_type == "usrp":
            usrp.set_rx_rate(sample_rates[val] * 1e6, 0)
        flush_buffer()

    def run(self):
        start_t = time.time()
        if sdr_type == "pluto":
            samples = sdr.rx() / 2**11
        elif sdr_type == "usrp":
            streamer.recv(recv_buffer, metadata)
            samples = recv_buffer[0]
        elif sdr_type == "sim":
            tone = np.exp(2j * np.pi * self.sample_rate * 0.1 * np.arange(fft_size) / self.sample_rate)
            noise = np.random.randn(fft_size) + 1j * np.random.randn(fft_size)
            samples = self.gain * tone * 0.02 + 0.1 * noise
            np.clip(samples.real, -1, 1, out=samples.real)
            np.clip(samples.imag, -1, 1, out=samples.imag)

        self.time_plot_update.emit(samples[0:time_plot_samples])
        PSD = 10.0 * np.log10(np.abs(np.fft.fftshift(np.fft.fft(samples)))**2 / fft_size)
        self.PSD_avg = self.PSD_avg * 0.99 + PSD * 0.01
        self.freq_plot_update.emit(self.PSD_avg)
        self.spectrogram[:] = np.roll(self.spectrogram, 1, axis=1)
        self.spectrogram[:, 0] = PSD
        self.waterfall_plot_update.emit(self.spectrogram)
        print("Frames per second:", 1 / (time.time() - start_t))
        self.end_of_run.emit()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("The PySDR Spectrum Analyzer")
        self.setFixedSize(QSize(1500, 1000))
        self.spectrogram_min = 0
        self.spectrogram_max = 0
        layout = QGridLayout()

        self.sdr_thread = QThread()
        self.sdr_thread.setObjectName('SDR_Thread')
        worker = SDRWorker()
        worker.moveToThread(self.sdr_thread)

        time_plot = pg.PlotWidget(labels={'left': 'Amplitude', 'bottom': 'Time [microseconds]'})
        time_plot.setMouseEnabled(x=False, y=True)
        time_plot.setYRange(-1.1, 1.1)
        time_plot_curve_i = time_plot.plot([])
        time_plot_curve_q = time_plot.plot([])
        layout.addWidget(time_plot, 1, 0)

        time_plot_auto_range_layout = QVBoxLayout()
        layout.addLayout(time_plot_auto_range_layout, 1, 1)
        auto_range_button = QPushButton('Auto Range')
        auto_range_button.clicked.connect(lambda: time_plot.autoRange())
        time_plot_auto_range_layout.addWidget(auto_range_button)
        auto_range_button2 = QPushButton('-1 to +1\n(ADC limits)')
        auto_range_button2.clicked.connect(lambda: time_plot.setYRange(-1.1, 1.1))
        time_plot_auto_range_layout.addWidget(auto_range_button2)

        freq_plot = pg.PlotWidget(labels={'left': 'PSD', 'bottom': 'Frequency [MHz]'})
        freq_plot.setMouseEnabled(x=False, y=True)
        freq_plot_curve = freq_plot.plot([])
        freq_plot.setXRange(center_freq / 1e6 - sample_rate / 2e6, center_freq / 1e6 + sample_rate / 2e6)
        freq_plot.setYRange(-30, 20)
        layout.addWidget(freq_plot, 2, 0)

        auto_range_button = QPushButton('Auto Range')
        auto_range_button.clicked.connect(lambda: freq_plot.autoRange())
        layout.addWidget(auto_range_button, 2, 1)

        waterfall_layout = QHBoxLayout()
        layout.addLayout(waterfall_layout, 3, 0)

        waterfall = pg.PlotWidget(labels={'left': 'Time [s]', 'bottom': 'Frequency [MHz]'})
        imageitem = pg.ImageItem(axisOrder='col-major')
        waterfall.addItem(imageitem)
        waterfall.setMouseEnabled(x=False, y=False)
        waterfall_layout.addWidget(waterfall)

        colorbar = pg.HistogramLUTWidget()
        colorbar.setImageItem(imageitem)
        colorbar.item.gradient.loadPreset('viridis')
        imageitem.setLevels((-30, 20))
        waterfall_layout.addWidget(colorbar)

        auto_range_button = QPushButton('Auto Range\n(-2σ to +2σ)')
        def update_colormap():
            imageitem.setLevels((self.spectrogram_min, self.spectrogram_max))
            colorbar.setLevels(self.spectrogram_min, self.spectrogram_max)
        auto_range_button.clicked.connect(update_colormap)
        layout.addWidget(auto_range_button, 3, 1)
        
        freq_slider = QSlider(Qt.Orientation.Horizontal)
        freq_slider.setRange(0, int(6e6))
        freq_slider.setValue(int(center_freq / 1e3))
        freq_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        freq_slider.setTickInterval(int(1e6))
        freq_slider.sliderMoved.connect(worker.update_freq)
        freq_label = QLabel()
        def update_freq_label(val):
            freq_label.setText("Frequency [MHz]: " + str(val / 1e3))
            freq_plot.autoRange()
        freq_slider.sliderMoved.connect(update_freq_label)
        update_freq_label(freq_slider.value())
        layout.addWidget(freq_slider, 4, 0)
        layout.addWidget(freq_label, 4, 1)

        gain_slider = QSlider(Qt.Orientation.Horizontal)
        gain_slider.setRange(0, 73)
        gain_slider.setValue(gain)
        gain_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        gain_slider.setTickInterval(2)
        gain_slider.sliderMoved.connect(worker.update_gain)
        gain_label = QLabel()
        def update_gain_label(val):
            gain_label.setText("Gain: " + str(val))
        gain_slider.sliderMoved.connect(update_gain_label)
        update_gain_label(gain_slider.value())
        layout.addWidget(gain_slider, 5, 0)
        layout.addWidget(gain_label, 5, 1)

        sample_rate_combobox = QComboBox()
        sample_rate_combobox.addItems([str(x) + ' MHz' for x in sample_rates])
        sample_rate_combobox.setCurrentIndex(0)
        sample_rate_combobox.currentIndexChanged.connect(worker.update_sample_rate)
        sample_rate_label = QLabel()
        def update_sample_rate_label(val):
            sample_rate_label.setText("Sample Rate: " + str(sample_rates[val]) + " MHz")
        sample_rate_combobox.currentIndexChanged.connect(update_sample_rate_label)
        update_sample_rate_label(sample_rate_combobox.currentIndex())
        layout.addWidget(sample_rate_combobox, 6, 0)
        layout.addWidget(sample_rate_label, 6, 1)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        def time_plot_callback(samples):
            time_plot_curve_i.setData(samples.real)
            time_plot_curve_q.setData(samples.imag)

        def freq_plot_callback(PSD_avg):
            f = np.linspace(freq_slider.value() * 1e3 - worker.sample_rate / 2.0, freq_slider.value() * 1e3 + worker.sample_rate / 2.0, fft_size) / 1e6
            freq_plot_curve.setData(f, PSD_avg)
            freq_plot.setXRange(freq_slider.value() * 1e3 / 1e6 - worker.sample_rate / 2e6, freq_slider.value() * 1e3 / 1e6 + worker.sample_rate / 2e6)

        def waterfall_plot_callback(spectrogram):
            imageitem.setImage(spectrogram, autoLevels=False)
            sigma = np.std(spectrogram)
            mean = np.mean(spectrogram)
            self.spectrogram_min = mean - 2 * sigma
            self.spectrogram_max = mean + 2 * sigma

        def end_of_run_callback():
            QTimer.singleShot(0, worker.run)

        worker.time_plot_update.connect(time_plot_callback)
        worker.freq_plot_update.connect(freq_plot_callback)
        worker.waterfall_plot_update.connect(waterfall_plot_callback)
        worker.end_of_run.connect(end_of_run_callback)
        self.sdr_thread.started.connect(worker.run)
        self.sdr_thread.start()

app = QApplication([])
window = MainWindow()
window.show()
signal.signal(signal.SIGINT, signal.SIG_DFL)
app.exec()

if sdr_type == "usrp":
    stream_cmd = uhd.types.StreamCMD(uhd.types.StreamMode.stop_cont)
    streamer.issue_stream_cmd(stream_cmd)