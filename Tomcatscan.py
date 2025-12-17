#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
from config.config_banners import banner
from config.config_console import Tomcat_Console


def run():
    print(banner)
    Tomcat_Console()

if __name__ == '__main__':
    run()

