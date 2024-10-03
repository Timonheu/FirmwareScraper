import scrapy
from firmwareScraper import nvdrequester


# Parent class that defines a standard implementation for the
# getCPE method used by the script that updates CPEs and CVEs.
class FirmwareScraperSpider(scrapy.Spider):
    def getCPE(self, data):
        return nvdrequester.NVDRequester().getCPE(data)
