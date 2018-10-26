#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Created on 2017-08-11 10:19:23
# Created by zhangguodong
# Project: CVE_Details

from pyspider.libs.base_handler import *
import re
from collections import defaultdict


# url = "www.cvedetails.com/cve/CVE-2007-6593/"
# pattern = "<table class=\"listtable\" .*?>.*?<tr.*?>.*?</tr>.*?(<tr.*?>.*?</tr>)+</table>"


class Handler(BaseHandler):
    crawl_config = {
    }

    def __init__(self):
        self.base_url = 'http://www.cvedetails.com/vulnerability-list/year-'
        self.start_year = 1999
        self.last_year = 2017

    @every(minutes=24 * 60)
    def on_start(self):
        while self.start_year <= self.last_year:
            url = self.base_url + str(self.start_year) + '/vulnerabilities.html'
            self.crawl(url, callback=self.index_page)
            self.start_year += 1

    @config(age=10 * 24 * 60 * 60)
    def index_page(self, response):
        for each in response.doc('#pagingb>a').items():
            self.crawl(each.attr.href, callback=self.list_page)

    def list_page(self, response):
        for each in response.doc('a[href^="http"]').items():
            if re.match("http://www.cvedetails.com/cve/CVE-\w+", each.attr.href, re.U):
                self.crawl(each.attr.href, callback=self.detail_page)

    @config(priority=2)
    def detail_page(self, response):
        products = list()
        versions = list()

        # for each in response.doc(' td').eq(3).items():
        # products.append(each.text())

        # for each in response.doc('#vulnprodstable>td').eq(4).items():

        count = 0
        for each in response.doc('#vulnprodstable td').items():
            count += 1
            if count % 9 == 5:
                versions.append(each.text())
            if count % 9 == 4:
                products.append(each.text())
                # versions.append(each.text())
        # print products
        # print versions
        p_v = zip(products, versions)
        p_v_list = list((product, version) for product, version in p_v)

        return {
            "cve_id": response.doc('#cvedetails>h1>a').text(),
            "(product,version)": p_v_list,
            "Product Type": response.doc('#vulnprodstable td ').eq(1).text(),
            "Vendor": response.doc('#vulnprodstable td ').eq(2).text(),
            # "Product":products,
            # "Version":versions,
            "url": response.url,
        }
