# -*- coding: utf-8 -*-
# from scapy.all import *
# 将一个pcap包分成若干个pcap包
# 为了解决大pcap分隔慢的问题，使用hash + dic进行辅助定位

import os
import dpkt
from dpkt.utils import inet_to_str
from spider_clash.myutils.logger import logger
from tqdm import tqdm
import json
from datetime import datetime
from spider_clash.myutils.config import config

# 获取当前时间
now = datetime.now()


datalink = 1


def get_packet_lengths(packet_bytes):
    """
    从bytes类型的数据包中获取有效负载长度（减去IP头部和TCP/UDP头部）。

    参数:
    packet_bytes -- 字节串，表示网络数据包

    返回:
    payload_length -- 有效负载长度（字节）
    """
    # 检查字节串是否足够长以包含以太网和IP头部
    # 确保IP头部存在（至少20字节）
    ETHERNET_HEADER_LENGTH = 14
    IP_HEADER_MIN_LENGTH = 20
    if len(packet_bytes) < 20:
        logger.warning("数据包太短，无法包含完整的IP头部。")
        return None, None

    ip_header_start = ETHERNET_HEADER_LENGTH

    # 获取IP头部的长度（第一个字节的低四位表示头部长度，以4字节为单位）
    ip_header_length = (packet_bytes[ip_header_start] & 0x0F) * 4

    # 检查IP头部长度是否有效
    if ip_header_length < IP_HEADER_MIN_LENGTH:
        logger.warning("IP头部长度无效。")
        return None, None

    # IP数据包长度（第16和17个字节，IP头部的第二个字段）
    ip_length_bytes = packet_bytes[
        ETHERNET_HEADER_LENGTH + 2 : ETHERNET_HEADER_LENGTH + 4
    ]

    ip_length = int.from_bytes(ip_length_bytes, byteorder="big")
    # IP协议类型（第10个字节）
    protocol = packet_bytes[ip_header_start + 9]

    # TCP头部或UDP头部的起始位置
    transport_header_start = ip_header_start + ip_header_length

    if protocol == 6:  # TCP
        # TCP头部长度（第12个字节的高4位，以4字节为单位）
        tcp_header_length = (packet_bytes[transport_header_start + 12] >> 4) * 4
        payload_length = ip_length - ip_header_length - tcp_header_length

    elif protocol == 17:  # UDP
        # UDP头部长度固定为8字节
        udp_header_length = 8
        payload_length = ip_length - ip_header_length - udp_header_length

    else:
        logger.warning("不支持的协议类型。")
        return None, None

    return payload_length


def getIP(datalink, pkt):
    IP = False
    if datalink == 1 or datalink == 239:  # ethernet frame
        IP = dpkt.ethernet.Ethernet(pkt).data
    # 是RAW_IP包，没有Ethernet层:
    elif datalink == 228 or datalink == 229 or datalink == 101:
        IP = dpkt.ip.IP(pkt)
        # dpkt.ip6.IP6
    else:
        logger.error("不认识的链路层协议!!!!")
    return IP


def get_payload_size(ip, pro_txt):
    ip_header_length = ip.hl * 4
    ip_total_length = ip.len
    if pro_txt == "TCP":
        transport_header_length = ip.data.off * 4
    elif pro_txt == "UDP":
        transport_header_length = 8  # UDP头部长度固定为8字节
    else:
        return None

    payload_size = ip_total_length - ip_header_length - transport_header_length
    return payload_size


def fenbao_and_restruct(file_name):
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
        for time, pkt in tqdm(pkts, desc="处理pcap文件"):
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
            payload = get_payload_size(ip, pro_txt)
            if payload is None:
                continue

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
                tcpstream[siyuanzu1].append([time, f"+{payload}"])
            elif siyuanzu2 in tcpstream:
                tcpstream[siyuanzu2].append([time, f"-{payload}"])
            else:
                if pro_txt == "TCP":
                    first_flag = getIP(datalink, pkt).data.flags
                    if first_flag != 2:
                        continue
                tcpstream[siyuanzu1] = []
                tcpstream[siyuanzu1].append([time, f"+{payload}"])

    except dpkt.dpkt.NeedData:
        logger.info(f"{file_name}PCAP capture is truncated, stopping processing...")
    f.close()
    return tcpstream


def flow2json(tcpstream, formatted_time, machine, behavior, dir, address):
    # 处理每个表格
    tcpstreams = []
    for stream in tqdm(tcpstream, desc="正在写入json文件"):
        # 分离数据到两个列表
        time_stamps = [item[0] for item in tcpstream[stream]]
        lengths = [item[1] for item in tcpstream[stream]]

        # 创建包含两个键的字典
        dict = {"timestamp": time_stamps, "length": lengths}
        dict["time"] = formatted_time
        (
            dict["src_ip"],
            dict["src_port"],
            dict["dst_ip"],
            dict["dst_port"],
            dict["protocol"],
        ) = stream.split("_")
        dict["machine"] = machine
        dict["behavior"] = behavior
        dict["address"] = address

        tcpstreams.append(dict)

    # 将所有表格转换为 JSON 格式的字符串
    json_lines = [json.dumps(stream, separators=(",", ":")) for stream in tcpstreams]
    json_data = "[\n" + ",\n".join(json_lines) + "\n]"

    # 将 JSON 字符串写入文件
    output_path = os.path.join(dir, f"{formatted_time}_{machine}_{behavior}_{address}.json")
    with open(output_path, "w") as json_file:
        json_file.write(json_data)

    logger.info(f"文件已保存{output_path}")
    return output_path


def cut(file_name, dir):
    """
    file_name：需要解包的pcap包
    dir：保存的路径
    """
    tcpstream = fenbao_and_restruct(file_name)
    machine = config["traffic"]["machine"]
    behavior = config["traffic"]["behavior"]
    os.makedirs(dir, exist_ok=True)
    # 将当前时间格式化为所需的字符串形式
    formatted_time = file_name.split("/")[-1].split("_")[0]
    address = ".".join(file_name.split("/")[-1].split("_")[1].split(".")[:-1])
    output_path = flow2json(tcpstream, formatted_time, machine, behavior, dir, address)
    return output_path


if __name__ == "__main__":
    source = "/home/aimafan/Document/mycode/handle_jp_isp/data/output.pcap"

    cut(source, "./test")
