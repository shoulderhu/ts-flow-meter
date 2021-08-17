from enum import IntEnum


class F(IntEnum):
    NO = 0
    TIME_RELATIVE = 1
    SRC = 2
    DST = 3
    TCP_SRCPORT = 4
    UDP_SRCPORT = 5
    TCP_DSTPORT = 6
    UDP_DSTPORT = 7
    IP_PRO = 8
    APP_PRO = 9
    TCP_STREAM = 10
    TCP_LEN = 11
    TCP_HDR_LEN = 12
    TCP_FLAGS = 13
    TCP_WINDOW_SIZE = 14
    UDP_STREAM = 15
    UDP_LENGTH = 16
    TCP_DUP_ACK_NUM = 17
    TCP_INIT_RTT = 18
    TCP_REUSED_PORTS = 19
    TCP_RETRANSMISSION = 20
    TCP_FAST_RETRANSMISSION = 21
    TCP_SPURIOUS_RETRANSMISSION = 22
    TCP_WINDOW_FULL = 23
    TCP_WINDOW_UPDATE = 24


NAME = ["No.", "Time", "Source", "Source Port", "Destination", "Destination Port", "Protocol", "IP Protocol", "Stream", "Duration",
        "Flow Pkt Len", "Flow Pkt Size", "Flow Pkt Size Min", "Flow Pkt Size Max", "Flow Pkt Size Mean", "Flow Pkt Size Std",
        "Fwd Pkt Len", "Fwd Pkt Size", "Fwd Pkt Size Min", "Fwd Pkt Size Max", "Fwd Pkt Size Mean", "Fwd Pkt Size Std",
        "Bwd Pkt Len", "Bwd Pkt Size", "Bwd Pkt Size Min", "Bwd Pkt Size Max", "Bwd Pkt Size Mean", "Bwd Pkt Size Std",
        "Flow Pkts/s", "Flow Bytes/s", "Fwd Pkts/s", "Fwd Bytes/s", "Bwd Pkts/s", "Bwd Bytes/s",
        "Flow IAT Total", "Flow IAT Min", "Flow IAT Max", "Flow IAT Mean", "Flow IAT Std",
        "Fwd IAT Total", "Fwd IAT Min", "Fwd IAT Max", "Fwd IAT Mean", "Fwd IAT Std",
        "Bwd IAT Total", "Bwd IAT Min", "Bwd IAT Max", "Bwd IAT Mean", "Bwd IAT Std",
        "Fwd PSH Flags", "Fwd URG Flags", "Bwd PSH Flags", "Bwd URG Flags",
        "Flow FIN Flags", "Flow SYN Flags", "Flow RST Flags", "Flow PSH Flags",
        "Flow ACK Flags", "Flow URG Flags", "Flow ECE Flags", "Flow CWR Flags",
        "Fwd Header Size", "Bwd Header Size", "Down/Up Ratio",
        "Fwd Window Size", "Bwd Window Size",
        "Fwd Payload Len",
        "Tcp Dup ACKs", "TCP Init Rtt", "TCP Reused Ports",
        "Tcp Retransmission", "Tcp Fast Retransmission", "Tcp Spurious Retransmission",
        "Tcp Window Full", "Tcp Window Update",
        "Label", "File Name"]
