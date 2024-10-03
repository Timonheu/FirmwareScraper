import scrapy
import re
from firmwareScraper.items import FirmwareScraperItem
from firmwareScraper import nvdrequester
from firmwareScraper.spiders import parent_spider


class linksysSpider(parent_spider.FirmwareScraperSpider):
    name = "linksys"
    vendor_name = "Linksys"
    vendor_url = "linksys.com"
    cpe_vendor_names = [name]

    allowed_domains = ["linksys.com"]
    start_urls = ["https://www.linksys.com/sitemap"]

    def parse(self, response):
        links = response.xpath("//a[@class='sitemap-list__link']/@href").extract()
        for link in links:
            yield scrapy.Request(url=link, callback=self.parse_product)

    def parse_product(self, response):
        download_url = response.xpath("//a[contains(text(),'FIRMWARE')]/@href").get()
        if download_url:
            yield scrapy.Request(url=download_url, callback=self.parse_download_page)

    def parse_download_page(self, response):
        # TODO: edge case with regional versions

        # Product name
        product_name = (
            response.xpath("//h1[contains(@class,'support-article__heading')]/text()")
            .get()
            .replace(" Downloads", "")
        )
        hardware_versions = response.xpath("//div[contains(@id,'version')]")
        for hardware_version_data in hardware_versions:
            hardware_version = (
                hardware_version_data.xpath("./@id")
                .get()
                .replace("version_", "")
                .replace("_", ".")
            )
            # Get a list of firmware listings
            all_listings = hardware_version_data.xpath(".//p")
            # Filter the ones that do not have '/firmware/' in the download URL.
            firmware_listings = [
                x for x in all_listings if x.xpath("./a[contains(@href, 'firmware/')]")
            ]
            for firmware_listing in firmware_listings:
                # will match only the version number
                version_re = re.compile(r"([0-9](\.[0-9]+)+)")
                # It is inconsistent, and any text can be in any number of spans.
                # So extract all that text first. As long as the version is fully
                # in either text or span this should work.
                text = firmware_listing.xpath("./text()").get()
                version_text = text if text else ""
                for span_text in firmware_listing.xpath("./span/text()").extract():
                    version_text = version_text + " " + span_text
                # Only get the first group, that is the full match
                version_matches = [x[0] for x in version_re.findall(version_text)]
                # Get the longest match, this is likely the version rather than the firmware size
                version = max(version_matches, key=len)
                download_url = firmware_listing.xpath("./a/@href").get()
                # Not extracting the build number for now, as it won't meaningfully improve results

                requester = nvdrequester.NVDRequester()
                cpe = self.getCPE(
                    {"name": product_name, "vendor": self.name, "version": version}
                )
                if cpe["cpe_name"] is not None:
                    yield cpe
                    for vulnerability in requester.get_CVE_items(cpe["cpe_name"]):
                        yield vulnerability

                firmware_item = FirmwareScraperItem()
                firmware_item["cpe_name"] = cpe["cpe_name"]
                firmware_item["name"] = product_name
                firmware_item["version"] = version
                firmware_item["file_url"] = download_url
                firmware_item["vendor_name"] = self.vendor_name
                yield firmware_item

    # Override parent class function
    def getCPE(self, data):
        # Set version_contain to True as some CPE versions include the build number
        return nvdrequester.NVDRequester().getCPE(data, version_contain=True)
