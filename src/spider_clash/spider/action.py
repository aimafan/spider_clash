from spider_clash.myutils import project_path
import os
import json
import random
from spider_clash.myutils.config import config
from spider_clash.myutils.logger import logger
import threading
from spider_clash.traffic.capture import capture, stop_capture
from spider_clash.traffic.cut_flow_dpkt import cut
import shutil
import subprocess
import time
from spider_clash.spider.spider import consume
import queue
from datetime import datetime


flag = queue.Queue()


def traffic(TASK_NAME, VPS_NAME, protocal):
    # 获取当前时间
    current_time = datetime.now()
    # 格式化输出
    formatted_time = current_time.strftime("%Y%m%d%H%M%S")
    logger.info("流量采集开始")

    traffic_name = capture(TASK_NAME, VPS_NAME, formatted_time, protocal)
    ok = flag.get()
    if ok == 1:
        cut(traffic_name, "../data/json")
    os.remove(traffic_name)


def browser_action():
    TASK_NAME = "browser"
    protocal = config["traffic"]["protocal"]
    url_path = os.path.join(project_path, "config", "my_list.txt")
    with open(url_path, "r") as file:
        url_list = file.read()
    logger.info(f"已从{url_path}中获取网站列表")
    url_list = url_list.split("\n")
    while True:
        random.shuffle(url_list)  # 洗牌url列表
        url = url_list[0]
        # 开流量收集
        traffic_thread = threading.Thread(
            target=traffic, args=(TASK_NAME, url.split("//")[-1], protocal)
        )
        traffic_thread.start()
        time.sleep(1)

        # 开代理
        clash_start_path = config["spider"]["clash_start_path"]
        clash_stop_path = config["spider"]["clash_stop_path"]
        process = subprocess.Popen(["bash", clash_start_path], stdout=subprocess.PIPE)
        output, error = process.communicate()
        if "OK" not in str(output):
            # 关流量
            stop_capture()
            flag.put(1)
            traffic_thread.join()
            time.sleep(1)
            continue
        logger.info("代理启动成功")

        # 浏览网页
        ok = consume(url)

        # 关代理
        subprocess.Popen(["bash", clash_stop_path], stdout=subprocess.PIPE)
        time.sleep(1)
        logger.info("代理关闭成功")

        # 关流量收集
        stop_capture()
        if ok:
            flag.put(1)
        else:
            flag.put(0)
        traffic_thread.join()
        time.sleep(1)


if __name__ == "__main__":
    browser_action()
