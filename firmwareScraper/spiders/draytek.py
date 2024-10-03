import scrapy
import urllib
import re
from firmwareScraper import nvdrequester
from firmwareScraper.items import FirmwareScraperItem
from firmwareScraper.spiders import parent_spider
from ftplib import FTP
import logging


class DraytekSpider(parent_spider.FirmwareScraperSpider):
    name = "draytek"
    vendor_name = "Draytek"
    vendor_url = "draytek.com"
    cpe_vendor_names = [name]
    allowed_domains = ["draytek.com.tw"]
    start_urls = ["https://fw.draytek.com.tw/"]
    directory_xpath = "//img[@alt='[DIR]']/parent::*/following-sibling::*/a"
    file_xpath = "//img[@alt='[   ]']/parent::*/following-sibling::*/a[not(contains(text(), 'Parent Directory'))]"

    # traverse this html page and use it to craft FTP URLs.
    def parse(self, response):
        directories = response.xpath(self.directory_xpath)
        for directory in directories:
            directory_url = directory.xpath("./@href").get()
            directory_name = directory.xpath("./text()").get()
            # Remove the '/' at the end
            name = directory_name[:-1]
            full_url = urllib.parse.urljoin(response.url, directory_url)

            yield scrapy.Request(
                url=full_url,
                callback=self.parse_directory,
                meta={"name": name, "relative_url": directory_name},
            )

    def parse_directory(self, response):
        directories = response.xpath(self.directory_xpath)
        firmware_directory = next(
            (
                dir
                for dir in directories
                if dir.xpath("./text()").get().lower() == "firmware/"
            ),
            None,
        )
        if firmware_directory:
            firmware_url = firmware_directory.xpath("./@href").get()
            full_url = urllib.parse.urljoin(response.url, firmware_url)
            yield scrapy.Request(
                url=full_url,
                callback=self.parse_firmware_directory,
                meta={
                    "name": response.meta["name"],
                    "relative_url": response.meta["relative_url"] + firmware_url,
                },
            )

    def parse_firmware_directory(self, response):
        version_re = re.compile(r"[vV][0-9]+(\.[0-9]+)+\/$")
        directories = response.xpath(self.directory_xpath)

        directories_to_download = [
            dir for dir in directories if version_re.search(dir.xpath("./text()").get())
        ]
        for directory in directories_to_download:
            directory_url = directory.xpath("./@href").get()
            # Remove 'v' and '/'
            version = directory.xpath("./text()").get()[1:-1]
            name = response.meta["name"]
            relative_url = response.meta["relative_url"] + directory_url
            cpe = self.getCPE(
                data={
                    "name": name,
                    "version": version,
                    "vendor": self.cpe_vendor_names[0],
                }
            )
            if cpe["cpe_name"]:
                yield cpe
                requester = nvdrequester.NVDRequester()
                for vulnerability in requester.get_CVE_items(cpe["cpe_name"]):
                    yield vulnerability
            firmware_item = FirmwareScraperItem()
            firmware_item["name"] = name
            firmware_item["version"] = version
            firmware_item["cpe_name"] = cpe["cpe_name"]
            firmware_item["file_url"] = "https://fw.draytek.com.tw/" + relative_url
            firmware_item["vendor_name"] = self.vendor_name
            firmware_item["file_urls"] = self.parse_directory_ftp(relative_url, [])

            yield firmware_item

    # Recursively find all download URLs through FTP
    def parse_directory_ftp(self, relative_directory_url, url_list):
        ftp = FTP("ftp.draytek.com")
        ftp.login()
        contents = [x for x in ftp.mlsd(path=relative_directory_url, facts=["type"])]
        # Keeping the connection alive for as short as possible, so it does not get aborted
        # while traversing the directory.
        ftp.quit()
        for name, facts in contents:
            if facts["type"] == "dir":
                new_relative_url = relative_directory_url + name + "/"
                for url in self.parse_directory_ftp(new_relative_url, url_list):
                    # mlsd seems to sometimes return duplicate URLs
                    if url not in url_list:
                        url_list.append(url)
            elif facts["type"] == "file":
                url = "https://fw.draytek.com.tw/" + relative_directory_url + name
                # mlsd seems to sometimes return duplicate URLs
                if url not in url_list:
                    # Download from the HTTPS website over FTP. Though either should be fine.
                    url_list.append(url)
        logging.debug("returning the urls: %s", url_list)
        return url_list
