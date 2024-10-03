import scrapy
import urllib
import json
import re
from firmwareScraper import nvdrequester
from firmwareScraper.items import FirmwareScraperItem
from datetime import datetime
from firmwareScraper.spiders import parent_spider


# Code adapted from the firmadyne firmware scraper
# https://github.com/firmadyne/scraper/blob/9822f224c9fa91d78e9022d308ebe4c9f2945324/firmware/spiders/dlink.py
class DLinkSpider(parent_spider.FirmwareScraperSpider):
    name = "dlink"
    vendor_name = "D-Link"
    vendor_url = "https://www.dlink.com"
    cpe_vendor_names = [name]

    allowed_domains = ["dlink.com"]
    start_urls = ["https://support.dlink.com/AllPro.aspx"]

    def parse(self, response):
        for product in response.xpath("//tr/td[1]/a/@alt").extract():
            yield scrapy.Request(
                url=urllib.parse.urljoin(
                    response.url, "ProductInfo.aspx?m=%s" % product
                ),
                headers={"Referer": response.url},
                meta={"name": product},
                callback=self.parse_product,
                cookies={"ServiceTypecookies": "ServiceType=2&ServiceTypeshow=1"},
            )

    # returns the Unix timestamp in miliseconds
    def get_unix_timestamp_ms():
        return (int)((datetime.now() - datetime(1970, 1, 1)).total_seconds() * 1000)

    def parse_product(self, response):
        for entry in response.xpath("//select[@id='ddlHardWare']/option"):
            revision = entry.xpath(".//text()").extract()[0]
            value = entry.xpath("./@value").extract()[0]

            if value:
                yield scrapy.Request(
                    url=urllib.parse.urljoin(
                        response.url,
                        "/ajax/ajax.ashx?d=%s&action=productfile&lang=en-US&ver=%s&ac_id=1"
                        % (DLinkSpider.get_unix_timestamp_ms(), value),
                    ),
                    headers={"Referer": response.url},
                    meta={"name": response.meta["name"], "revision": revision},
                    callback=self.parse_json,
                )

    def parse_json(self, response):
        # The Firmadyne scraper checks whether there is an MIB file,
        # not doing this for now but might be a worthwhile addition.
        json_response = json.loads(response.text)
        for entry in json_response["item"]:
            for file in entry["file"]:
                if file["filetypename"].lower() == "firmware" or file["isFirmF"] == "1":
                    # some updates should apparently be downloaded through
                    # an app, in which case the download button only points
                    # to release notes.
                    # These are (for now) filtered out by checking the file
                    # extension.
                    firmware_url = file["url"]
                    if firmware_url.endswith(".pdf"):
                        continue
                    product_name = response.meta["name"]
                    # TODO: improve way of getting version name, this is very ad-hoc
                    # TODO: make a reusable function for finding versions, like the
                    # firmadyne scraper
                    file_name = file["name"]
                    version_re = re.compile(r"[0-9]+(\.[0-9A-Z]+)+")
                    version_match = version_re.search(file_name)

                    # a very ad-hoc way of dealing with a rare edge case
                    if version_match is None:
                        version_re = re.compile(r"[0-9]+[0-9A-Z]+")
                        version_match = version_re.search(file_name)
                    version = version_match.group(0)

                    data = {
                        "vendor": self.name,
                        "name": product_name,
                        "version": version,
                    }
                    # Use the parent class implementation
                    cpe = self.getCPE(data)

                    # Ensure the CPE gets inserted first.
                    firmware_item = FirmwareScraperItem()

                    requester = nvdrequester.NVDRequester()
                    if cpe["cpe_name"] is not None:
                        yield cpe
                        for vulnerability in requester.get_CVE_items(cpe["cpe_name"]):
                            yield vulnerability

                    # is none if there is no matching CPE
                    firmware_item["cpe_name"] = cpe["cpe_name"]
                    firmware_item["name"] = product_name
                    firmware_item["version"] = version
                    firmware_item["file_url"] = firmware_url

                    firmware_item["vendor_name"] = self.vendor_name
                    yield firmware_item
