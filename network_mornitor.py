import pyshark

network_interface = 'Wi-Fi'
capture = pyshark.LiveCapture(interface=network_interface, )

try:
    for packet in capture.sniff_continuously():
        print(f" packet capture: {packet}")
except KeyboardInterrupt:
    print("Capture stopped.")