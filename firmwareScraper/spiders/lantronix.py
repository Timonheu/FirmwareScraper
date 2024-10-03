from ftplib import FTP
import scrapy
from firmwareScraper import nvdrequester
from firmwareScraper.items import FirmwareScraperItem
from firmwareScraper.spiders import parent_spider
from urllib.parse import urljoin, unquote
import re
import logging


# This spider is very oppurtunistic, and only scrapes directories that
# contain a version directory at the root, which contains at least one
# file with a deisred extension (as defined in desired_extensions, an
# extension is set to lowercase before the check).
# There are examples of directories with firmware that do not adhere to
# this format, these are ignored by this scraper for the sake of
# simplicity and accuracy.
class LantronixSpider(parent_spider.FirmwareScraperSpider):
    name = "lantronix"
    vendor_name = "Lantronix"
    vendor_url = "lantronix.com"
    cpe_vendor_names = [name]
    allowed_domains = ["ts.lantronix.com"]
    start_urls = ["https://ts.lantronix.com/ftp/"]
    # Extensions in this list should be lowercase,
    # extensions are cast to lowercase before checking against
    # this list.
    desired_extensions = [".sys", ".rom", ".romz", ".bin"]

    def parse(self, response):
        directories = response.xpath("//a")
        for directory in directories:
            # Without an unquote the FTP server can get confused
            relative_url = unquote(directory.xpath("./@href").get())
            if len(relative_url) <= 1 or relative_url[-1] != "/":
                # This is not a directory
                continue
            name = directory.xpath("./text()").get()
            full_url = urljoin(response.url, relative_url)

            yield scrapy.Request(
                url=full_url,
                callback=self.parse_directory,
                meta={"name": name},
            )

    def parse_directory(self, response):
        version_directories = response.xpath(
            "//a[re:test(text(),'[vV]?[0-9]+(\.[0-9]+)+([Rr][0-9]+)?')]"
        )
        for directory in version_directories:
            version = directory.xpath("./text()").get()
            # Remove the leading v or V if present
            version = (
                version[1:]
                if version.startswith("v") or version.startswith("V")
                else version
            )
            # Without an unquote the FTP server can get confused
            relative_url = unquote(directory.xpath("./@href").get())
            full_url = urljoin(response.url, directory.xpath("./@href").get())
            # Check if a file in this directory has one of the desired extensions
            ftp_relative_url = relative_url.replace("/ftp", "pub")
            if self.check_extensions(ftp_relative_url):
                name = response.meta["name"]
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
                firmware_item["file_url"] = full_url
                firmware_item["vendor_name"] = self.vendor_name

                # Parse the version directory
                firmware_item["file_urls"] = self.parse_directory_ftp(
                    ftp_relative_url, []
                )
                yield firmware_item

    def check_extensions(self, relative_directory_url):
        extension_re = re.compile(r"\.[0-9a-zA-Z]+$")
        ftp = FTP("ftp.lantronix.com")
        ftp.login()
        contents = [x for x in ftp.mlsd(path=relative_directory_url, facts=["type"])]
        ftp.quit()
        for name, facts in contents:
            if facts["type"] == "file":
                extension = extension_re.search(name)
                if extension and extension.group(0).lower() in self.desired_extensions:
                    return True
        return False

    def parse_directory_ftp(self, relative_directory_url, url_list):
        ftp = FTP("ftp.lantronix.com")
        ftp.login()
        contents = [x for x in ftp.mlsd(path=relative_directory_url, facts=["type"])]
        ftp.quit()
        for name, facts in contents:
            if facts["type"] == "dir":
                new_relative_url = relative_directory_url + name + "/"
                for url in self.parse_directory_ftp(new_relative_url, url_list):
                    # mlsd seems to sometimes return duplicate URLs
                    if url not in url_list:
                        url_list.append(url)
            elif facts["type"] == "file":
                https_relative_url = relative_directory_url.replace("pub", "ftp")
                url = "https://ts.lantronix.com/" + https_relative_url + name
                # mlsd seems to sometimes return duplicate URLs
                if url not in url_list:
                    # Download from the HTTPS website over FTP. Though either should be fine.
                    url_list.append(url)
        return url_list
