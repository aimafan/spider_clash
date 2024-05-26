# -*- coding: utf-8 -*-
# from scapy.all import *
# 将一个pcap包分成若干个pcap包
# 为了解决大pcap分隔慢的问题，使用hash + dic进行辅助定位

import os
import dpkt
from dpkt.utils import inet_to_str
from handle_jp_isp.myutils.logger import logger
from tqdm import tqdm

datalink = 1


def get_packet_lengths(packet_bytes):
    """
    从bytes类型的数据包中获取以太网帧长度和IP数据包长度。

    参数:
    packet_bytes -- 字节串，表示网络数据包

    返回:
    eth_length -- 以太网帧的总长度（字节）
    ip_length -- IP数据包的总长度（字节）
    """
    # 检查字节串是否足够长以包含以太网和IP头部
    # 确保IP头部存在（至少20字节）
    if len(packet_bytes) < 20:
        logger.warning("数据包太短，无法包含完整的IP头部。")

    # IP数据包长度（第16和17个字节，IP头部的第二个字段）
    ip_length_bytes = packet_bytes[16:18]
    ip_length = int.from_bytes(ip_length_bytes, byteorder="big")

    return ip_length


def getIP(datalink, pkt):
    IP = False
    if datalink == 1 or datalink == 239:  # ethernet frame
        IP = dpkt.ethernet.Ethernet(pkt).data
    # 是RAW_IP包，没有Ethernet层:
    elif datalink == 228 or datalink == 229 or datalink == 101:
        IP = dpkt.ip.IP(pkt)
    else:
        logger.error("不认识的链路层协议!!!!")
    return IP


def fenbao_and_restruct(file_name, flags, jieduan):
    tcpstream = {}
    f = open(file_name, "rb")
    try:
        pkts = dpkt.pcap.Reader(f)
    except ValueError:
        f.close()
        f = open(file_name, "rb")
        pkts = dpkt.pcapng.Reader(f)
    except Exception as e:
        logger.error(f"打开{file_name}的过程中发生错误：{e}")
        f.close()
        return tcpstream
    global datalink
    datalink = pkts.datalink()
    try:
        for time, pkt in tqdm(pkts):
            # print(pkt)
            ip = getIP(datalink, pkt)
            if not isinstance(ip, dpkt.ip.IP):
                # logger.warn("不是IP层")
                continue
            if isinstance(ip.data, dpkt.udp.UDP):
                pro_txt = "UDP"
            elif isinstance(ip.data, dpkt.tcp.TCP):
                pro_txt = "TCP"
            else:
                # logger.warn("不是TCP或UDP协议")
                continue
            pro = ip.data
            # 未知
            srcport = pro.sport
            dstport = pro.dport
            srcip = inet_to_str(ip.src)
            dstip = inet_to_str(ip.dst)
            siyuanzu1 = (
                srcip
                + "_"
                + str(srcport)
                + "_"
                + dstip
                + "_"
                + str(dstport)
                + "_"
                + pro_txt
            )
            siyuanzu2 = (
                dstip
                + "_"
                + str(dstport)
                + "_"
                + srcip
                + "_"
                + str(srcport)
                + "_"
                + pro_txt
            )
            if siyuanzu1 in tcpstream:
                tcpstream[siyuanzu1].append([time, pkt])
            elif siyuanzu2 in tcpstream:
                tcpstream[siyuanzu2].append([time, pkt])
            else:
                tcpstream[siyuanzu1] = []
                tcpstream[siyuanzu1].append([time, pkt])

    except dpkt.dpkt.NeedData:
        logger.info(f"{file_name}PCAP capture is truncated, stopping processing...")
    f.close()
    return tcpstream


def save_file(dir, tcpstream, flags, filename, deletetype, minlength):
    l = len(tcpstream)
    pcap_list = []
    for stream in tcpstream:
        name_stream = stream.split("_")
        name = (
            f"{dir}/"
            + filename
            + "_"
            + str(name_stream[4])
            + "_"
            + str(name_stream[0])
            + "_"
            + str(name_stream[1])
            + "_"
            + str(name_stream[2])
            + "_"
            + str(name_stream[3])
            + ".pcap"
        )
        try:
            with open(name, "wb") as f:
                for i in range(len(tcpstream[stream])):
                    payload_len = get_packet_lengths(tcpstream[stream][i][1]) - 40
                    zeros = b"\x00" * payload_len
                    tcpstream[stream][i][1] += zeros
                writer = dpkt.pcap.Writer(f, linktype=datalink)
                writer.writepkts(tuple(tcpstream[stream]))
            pcap_list.append(name)
        except Exception as e:
            logger.error(f"切流中发生错误：{e}")
    return pcap_list


def cut(file_name, dir):
    """
    file_name：需要解包的pcap包
    dir：保存的路径
    """
    flags = []
    jieduan = None
    # file_data = read_pcap(file_name)
    tcpstream = fenbao_and_restruct(file_name, flags, jieduan)
    namespace = file_name.split("/")
    args = "i2p_" + namespace[-1][:-5]
    deletetype = []
    minlength = 5
    os.makedirs(dir, exist_ok=True)
    pcap_list = save_file(dir, tcpstream, flags, args, deletetype, minlength)
    return pcap_list


if __name__ == "__main__":
    source = (
        "/mnt/10TB/traffic_datasets/i2p/vps3/data/browser/row_pcap/20240509015324.pcap"
    )

    cut(source, "/mnt/10TB/traffic_datasets/i2p/vps3/data/browser/handled_pcap")
