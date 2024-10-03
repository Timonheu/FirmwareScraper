import scrapy
import logging
import requests
from firmwareScraper.spiders import parent_spider
from firmwareScraper.items import FirmwareScraperItem
from firmwareScraper import nvdrequester


class TendaSpider(parent_spider.FirmwareScraperSpider):
    name = "tenda"
    vendor_name = "Tenda"
    vendor_url = "tendacn.com"
    cpe_vendor_names = [name]

    allowed_domains = ["tendacn.com"]
    start_urls = ["https://www.tendacn.com/download/3.html"]

    def parse(self, response):
        next = response.xpath("//a[@class='page'][contains(text(), '>')]")
        if next:
            # There is a next page, call this function on that page before continuing
            # This means the website will be scraped from last page to first.
            yield scrapy.Request(
                url=response.urljoin(next.xpath("./@href").get()), callback=self.parse
            )
        listed_firmwares = response.xpath("//a[@class='dfbr-dinfo']")
        for firmware in listed_firmwares:
            # For some reason the first two characters are '/', need to prepend the scheme
            url = "https:" + firmware.xpath("./@href").get()
            yield scrapy.Request(url=url, callback=self.parse_firmware_page)

    def parse_firmware_page(self, response):
        full_name = response.xpath(
            "//h2[contains(@class, 'featurette-heading')]/text()"
        ).get()
        if not full_name:
            # something is wrong with this page, abort
            logging.debug("No name found on %s", response.url)
            return
        split_name = full_name.split("\xa0")
        product_name = split_name[0].strip()
        if "Firmware" not in product_name:
            # This is most likely not firmware, abort
            return
        # Remove the word "Firmware" from the name
        product_name = product_name.replace("Firmware", "").strip()
        if split_name[1]:
            # This is one piece of firmware
            # There are also some firmware bundles, handling them would be a lot of
            # effort for minimal gain, so this is the only case that is handled.
            version = split_name[1].strip()
            # remove version from name, this is a rare edge case
            product_name = product_name.replace(version, "").strip()
            # Skip the V
            if version[0] == "V":
                version = version[1:]

            # This url also starts with '//', include the scheme
            file_url = (
                "https:"
                + response.xpath("//a[contains(@class, 'btnDown')]/@href").get()
            )
            # This site contains some non-existant URLs, bettter nip them in the bud,
            # before inserting CPE and CVE information
            if requests.head(file_url).status_code == 404:
                logging.debug(
                    f"Url {file_url} for firmware {product_name} returned a 404."
                )
                return

            # In version remove spaces and escape brackets before sending it off to the NVD
            cpe_version = version.replace(" ", "").replace("(", "\(").replace(")", "\)")
            cpe = self.getCPE(
                data={
                    "name": product_name,
                    "version": cpe_version,
                    "vendor": self.cpe_vendor_names[0],
                }
            )
            if cpe["cpe_name"] is not None:
                yield cpe
                requester = nvdrequester.NVDRequester()
                for vulnerability in requester.get_CVE_items(cpe["cpe_name"]):
                    yield vulnerability

            firmware_item = FirmwareScraperItem()
            firmware_item["name"] = product_name
            firmware_item["version"] = version
            firmware_item["cpe_name"] = cpe["cpe_name"]
            firmware_item["file_url"] = file_url
            firmware_item["vendor_name"] = self.vendor_name
            yield firmware_item
