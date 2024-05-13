from spider_clash.myutils.logger import logger
from spider_clash.myutils.config import config
from spider_clash.spider.action import browser_action


def main():
    mode = config["spider"]["mode"]
    logger.info(f"开始捕获流量，模式{mode}")
    if mode == "browser":
        browser_action()


if __name__ == "__main__":
    main()
