import scrapy
from firmwareScraper import nvdrequester
from firmwareScraper.items import FirmwareScraperItem
import re
import logging
from firmwareScraper.spiders import parent_spider


class TPLinkGlobalSpider(parent_spider.FirmwareScraperSpider):
    name = "tp-link"
    vendor_name = "TP-Link"
    vendor_url = "https://www.tp-link.com/en"
    cpe_vendor_names = [name]
    start_urls = ["https://www.tp-link.com/en/support/download/"]

    def parse(self, response):
        relative_urls = response.xpath(
            "//div[@class='download-center-list']/div[not(@class='business-res item')]/.//a[@class='ga-click']/@href"
        ).extract()
        for relative_url in relative_urls:
            product_page = response.urljoin(relative_url)
            yield scrapy.Request(product_page, callback=self.parse_product)

    def parse_product(self, response):
        versions = response.xpath("//dl[@class='select-version']/.//a/@href")
        logging.debug("Reached a product page.")
        if versions:  # there are multiple hardware versions
            logging.debug("Product has multiple versions.")
            # List of strings that signify the hardware version
            # List of urls to these hardware versions
            versions_urls = versions.extract()
            for i in range(len(versions_urls)):
                yield scrapy.Request(
                    url=versions_urls[i],
                    callback=self.parse_hardware_version,
                )
        else:
            self.parse_hardware_version(response)

    def parse_hardware_version(self, response):
        logging.debug("Looking for firmware images.")
        relative_firmware_url = response.xpath(
            "//ul[@class='nav-tabs']/li[@data-id='Firmware']/a/@href"
        ).get()
        # is now either '#Firmware' or None. In the latter case the
        # journey ends here.
        if relative_firmware_url:
            # There is firmware here! Don't actually need to use the
            # relative url, as the content is already here
            firmwares = response.xpath(
                "//div[@id='content_Firmware']/table[@class='download-resource-table']"
            )
            model_name = (
                response.xpath("//em[@id='model-version-name']/text()").get().strip()
            )
            logging.debug("Firmware images found for %s", model_name)
            for firmware in firmwares:
                download_url = firmware.xpath(
                    ".//a[@class='download-resource-btn ga-click']/@href"
                ).get()
                if not download_url:
                    # download is stuck behind a region event
                    download_url = firmware.xpath(
                        ".//a[text()='Still Download']/@href"
                    ).get()
                # Full name to be split up for further metadata collection
                full_name = firmware.xpath(
                    ".//th[@class='download-resource-name']/p/text()"
                ).get()
                logging.debug("Collecting %s", full_name)
                # Extracts the (version) number present in names that is based
                # on date. These numbers are between 6 and 8 digits, and at the
                # end of the name.
                version_re = re.compile(r"[^0-9][0-9]{6,8}")
                version = version_re.search(full_name)
                # Might be None in some rare cases
                if version:
                    version = version.group(0)[1:]
                else:
                    # Empty string is the easiest for CPE matching
                    version = ""
                hardware_version = response.xpath(
                    "//span[@id='verison-hidden']/text()"
                ).get()  # This typo is how it is found on the website.
                # Add the hardware version to the name
                hw_ver_name = (
                    model_name + " " + hardware_version
                    if hardware_version
                    else model_name
                )
                # If no version can be selected just keep the version emtpy
                # for the CPE match
                if not response.xpath("//dl[@class='select-version']"):
                    hardware_version = ""

                requester = nvdrequester.NVDRequester()
                cpe = requester.getCPE(
                    data={"name": model_name, "vendor": self.name, "version": version},
                    version_contain=True,
                    secondary_version=hardware_version,
                )
                if cpe["cpe_name"] is not None:
                    yield cpe
                    for vulnerability in requester.get_CVE_items(cpe["cpe_name"]):
                        yield vulnerability

                if not version:
                    # now for the name used in the database and filesystem instead of ""
                    version = "no_version"

                firmware_item = FirmwareScraperItem()

                firmware_item["cpe_name"] = cpe["cpe_name"]
                firmware_item["name"] = hw_ver_name
                firmware_item["version"] = version
                firmware_item["file_url"] = download_url
                firmware_item["vendor_name"] = self.vendor_name

                yield firmware_item

    # A bit of a roundabout way, only used by the script that updates CPEs and CVEs. Overrides
    # a function of the parent class.
    def getCPE(self, data):
        hw_ver_re = re.compile(r"(V[0-9]+(\.?[0-9]+)?)$")
        # Extract the hardware version
        hardware_version = hw_ver_re.search(data["name"])
        hardware_version = hardware_version.group(0) if hardware_version else ""
        # Remove the hardware version from the name
        data["name"] = hw_ver_re.sub("", data["name"]).strip()
        # Request the CPE
        return nvdrequester.NVDRequester().getCPE(
            data, version_contain=True, secondary_version=hardware_version
        )
