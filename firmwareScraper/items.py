# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class FirmwareScraperItem(scrapy.Item):
    # define the fields for your item here like:
    # name = scrapy.Field()

    # metadata for a piece of firmware
    name = scrapy.Field()
    version = scrapy.Field()
    file_url = scrapy.Field()
    file_urls = scrapy.Field()

    # additional metadata
    vendor_name = scrapy.Field()

    cpe_name = scrapy.Field()


class CPEItem(scrapy.Item):
    cpe_name = scrapy.Field()
    cpe_name_id = scrapy.Field()


class CVEItem(scrapy.Item):
    # metadata for a vulnerablity
    cve_id = scrapy.Field()
    description = scrapy.Field()
    references = scrapy.Field()
    vendor_comments = scrapy.Field()

    # The cpe from which this vulnerability was found
    # (and to which this vulnerability should be linked)
    cpe_name = scrapy.Field()

    # list of CWEItem objects associated with this vulnerability
    cwe_items = scrapy.Field()


# Making this a separate item, so it can be handled in
# its own way
class CWEItem(scrapy.Item):
    cwe_id = scrapy.Field()
    source = scrapy.Field()
    source_type = scrapy.Field()

    # the cve from which this weakness was found
    # (and to which this vulnerablity should be linked)
    cve_id = scrapy.Field()
