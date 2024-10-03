import scrapy
from firmwareScraper import nvdrequester
from firmwareScraper.items import FirmwareScraperItem
from firmwareScraper.spiders import parent_spider


# Visits all product suppport pages, and scrapes the firmware download url if there is one.
class MoxaSpider(parent_spider.FirmwareScraperSpider):
    name = "moxa"
    vendor_name = "Moxa"
    vendor_url = "https://www.moxa.com"
    cpe_vendor_names = [name]
    start_urls = [
        "https://www.moxa.com/en/support/product-support/software-and-documentation"
    ]

    def parse(self, response):
        product_relative_urls = response.xpath(
            "//li[@class='search-dropdown__item']/a/@href"
        )
        for relative_url in product_relative_urls.getall():
            product_page = response.urljoin(relative_url)
            yield scrapy.Request(product_page, callback=self.parse_product)

    def parse_product(self, response):
        base_query = "//tr[@data-filter='sw-{$moxa.category.firmware$}']"
        if response.xpath(base_query).get() is not None:  # If this page has firmware
            version = (
                response.xpath(base_query + "//span[@class='version-short']/text()")
                .get()
                .replace("v", "")
                .strip()
            )
            product_name = (
                response.xpath("//span[@class='breadcrumb__current']/text()")
                .get()
                .replace(" Series", "")
                .strip()
            )

            firmware_url = response.xpath(
                "//div[@class='flex-between']/a[@data-type='Firmware']/@href"
            ).get()

            requester = nvdrequester.NVDRequester()
            cpe = self.getCPE(
                {
                    "vendor": self.name,
                    "name": product_name,
                    "version": version,
                }
            )
            firmware_item = FirmwareScraperItem()

            # Ensure the CPE gets inserted first.
            if cpe["cpe_name"] is not None:
                yield cpe
                for vulnerability in requester.get_CVE_items(cpe["cpe_name"]):
                    yield vulnerability

            # is None if there is no matching CPE
            firmware_item["cpe_name"] = cpe["cpe_name"]
            firmware_item["name"] = product_name
            firmware_item["version"] = version
            firmware_item["file_url"] = firmware_url

            firmware_item["vendor_name"] = self.vendor_name
            yield firmware_item
