# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html


# useful for handling different item types with a single interface
# below import is as of yet unused, and also gives an error
# from itemadapter import itemadapter
from firmwareScraper.items import FirmwareScraperItem, CPEItem, CVEItem
from scrapy.pipelines.files import FilesPipeline
from firmwareScraper.internet_archive_uploader import InternetArchiveUploader
from scrapy.utils.project import get_project_settings
from scrapy import Request
import psycopg
import hashlib
from zipfile import ZipFile
from pathlib import PurePosixPath, Path
import logging
import os
import urllib
from difflib import SequenceMatcher
from firmwareScraper import database_insertions


# TODO: Filter items in get_media_requests like the firmadyne scraper
class FirmwarescraperPipeline(FilesPipeline):
    def __init__(self, store_uri, download_func=None, settings=None):
        # vendor_name of vendors for which you want to allow multiple firmwares to
        # have the same CPE.
        self.DO_NOT_DEDUPLICATE_CPES = ["TP-Link"]
        # Files will be uploaded to the internet archive when set to TRUE/True/true
        # Only evaluates to True if the environment variable is equal to True (case insensitve)
        self.UPLOAD_TO_IA = (
            os.environ.get("UPLOAD_TO_IA", default="False").lower() == "true"
        )

        # connection details
        hostname = "db"
        username = "postgres"
        password = open("db/password.txt", "r").read()
        database = "metadata"

        # string passed as argument to start a connection with our db
        self.connection_params = (
            "host="
            + hostname
            + " user="
            + username
            + " password="
            + password
            + " dbname="
            + database
        )
        # Ensure all tables are present, if not create them
        with psycopg.connect(self.connection_params) as connection:
            with connection.cursor() as cur:
                query = open("db/init.sql", "r").read()
                cur.execute(query)

        logging.info("Database tables have been initialized.")
        super(FirmwarescraperPipeline, self).__init__(
            store_uri, download_func, settings
        )

    # This does not seem necessary in this case, I just keep the connection
    # parameters hardcoded. A bit dirty but should work fine.
    # Might want to change this when writing a second pipeline.
    # @classmethod
    # def from_crawler(cls, crawler):
    #     return cls()

    # overrides method from FilesPipeline
    def file_path(self, request, response=None, info=None, *, item=None):
        url_hash = self.__get_url_hash(request.url)
        extension = os.path.splitext(
            os.path.basename(urllib.parse.urlsplit(request.url).path)
        )[1]
        vendor_name = self.clean_name(item["vendor_name"])
        name = self.clean_name(item["name"])
        version = self.clean_name(item["version"])
        path = self.__create_file_path(vendor_name, name, version, url_hash, extension)
        logging.debug("File path: %s", path)
        return path

    def __get_url_hash(self, url):
        return hashlib.shake_256(url.encode()).hexdigest(5)

    def __create_file_path(self, vendor_name, name, version, url_hash, extension):
        return vendor_name + "/" + name + "/" + version + "/" + url_hash + extension

    # Replaces special characters that can't be used in file path names
    def clean_name(self, string):
        result = string.replace("/", "&")
        result = result.replace("\\", "&")
        if result == ".":
            result = "period"
        if result == "..":
            result = "double period"
        result = result.replace(":", "|")
        result = result.replace(";", "|")
        return result

    # Opens the connection and inserts the vendor
    def open_spider(self, spider):
        self.connection = psycopg.connect(
            self.connection_params, row_factory=psycopg.rows.dict_row
        )
        logging.info("Database connection established.")
        cursor = self.connection.cursor()
        # check if this firmware already has an entry with the same name,
        # version and vendor.
        try:
            cursor.execute(
                "SELECT * FROM vendor WHERE vendor_name = %s",
                (spider.vendor_name,),
            )
        except BaseException as e:
            logging.error(
                "%s encountered when querying for vendor %s", e, spider.vendor_name
            )
            raise
        result = cursor.fetchone()
        logging.debug("Vendor name result: %s", result)
        if result:
            logging.warning(
                """
                There is already and existing vendor entry with:
                vendor_name: %s
                This vendor data will not be inserted.
                """,
                spider.vendor_name,
            )
        else:
            try:
                with self.connection.cursor() as cursor:
                    # First insert vendor
                    cursor.execute(
                        """
                        INSERT INTO vendor (
                            vendor_name,
                            vendor_url
                        ) VALUES (%s, %s);
                        """,
                        (spider.vendor_name, spider.vendor_url),
                    )
            except BaseException as e:
                logging.error(
                    "%s encountered when inserting vendor name %s",
                    e,
                    spider.vendor_name,
                )
                self.connection.rollback()
            else:
                self.connection.commit()

        logging.debug("Vendor insertion completed.")
        self.uploader = InternetArchiveUploader()

        super(FirmwarescraperPipeline, self).open_spider(spider)

    def close_spider(self, spider):
        self.connection.close()
        # check CPEs that match multiple firmwares, and only keep the best match
        # don't do this for tp-link, as the CPEs that get matched to multiple
        # devices simply match to multiple hardware versions, better to keep the duplicates
        with psycopg.connect(
            self.connection_params, row_factory=psycopg.rows.dict_row
        ) as connection:
            duplicates_query = """
                SELECT *
                FROM firmware
                WHERE cpe_name IN (
                    SELECT cpe_name
                    FROM firmware
                    GROUP BY cpe_name
                    HAVING COUNT(*) > 1
                );
                """
            cursor = connection.execute(duplicates_query)
            result = cursor.fetchall()
            # Creating a list for each separate cpe.
            # grouped_firmware will be a dict of lists,
            # each list will correspond to one cpe.
            grouped_firmware = {}
            for d in result:
                if d["vendor"] not in self.DO_NOT_DEDUPLICATE_CPES:
                    # for each dict get the cpe name
                    cpe_name = d["cpe_name"]
                    # if there is no entry for this cpe yet:
                    if cpe_name not in grouped_firmware:
                        grouped_firmware[cpe_name] = [d]
                    else:
                        grouped_firmware[cpe_name].append(d)
            # For each distinct CPE:
            for cpeName in grouped_firmware:
                firmware_list = grouped_firmware[cpeName]
                logging.debug(
                    """
                    Firmware images with the same cpe:
                    cpe: %s
                    names: %s
                    """,
                    cpeName,
                    [x["name"] for x in firmware_list],
                )
                prepared_cpeName = cpeName.replace("\:", "")
                product_substring = prepared_cpeName.split(":")[4]
                best_id = None
                best_name = None
                best_match = 0
                for firmware in firmware_list:
                    match = SequenceMatcher(
                        isjunk=lambda x: x in "\\",
                        a=product_substring,
                        b=firmware["name"].lower(),
                    ).ratio()
                    if match > best_match:
                        best_match = match
                        best_id = firmware["id"]
                        best_name = firmware["name"]
                logging.debug("best matching name is %s", best_name)
                try:
                    # set cpe_name to null if the cpe_name is equal to cpeName
                    # and the id is not equal to best_id
                    cursor = connection.execute(
                        """
                        UPDATE firmware
                        SET cpe_name = NULL
                        WHERE id != %s AND cpe_name = %s;
                        """,
                        (best_id, cpeName),
                    )
                except BaseException as e:
                    connection.rollback()
                    raise e
                else:
                    connection.commit()
            check_result = connection.execute(duplicates_query).fetchall()
            if (
                len(
                    [
                        x
                        for x in check_result
                        if x["vendor"] not in self.DO_NOT_DEDUPLICATE_CPES
                    ]
                )
                > 0
            ):
                logging.error(
                    """
                    There are still CPEs that are linked to multiple firmwares:
                    %s
                    """,
                    check_result,
                )

    def get_media_requests(self, item, info):
        if isinstance(item, FirmwareScraperItem):
            if "file_urls" in item:
                for url in item["file_urls"]:
                    logging.debug("Yielding download request for %s", url)
                    yield Request(url)
            else:
                url = item["file_url"]
                yield Request(url)

    def item_completed(self, results, item, spider):
        logging.debug(
            """
            Item completed, inserting data into database.
            Results: %s""",
            results,
        )
        # only execute this for cpe items
        if isinstance(item, CPEItem):
            database_insertions.cpe_insertion(item, self.connection)

        # only execute this for firmware items
        if isinstance(item, FirmwareScraperItem):
            self.firmware_post_download(item, results)

        if isinstance(item, CVEItem):
            database_insertions.cve_insertion_update(item, self.connection)
        return item

    def firmware_post_download(self, item, results):
        logging.debug("Download complete, results: %s", results)
        if "file_urls" in item:
            # There are multiple files, so put them all together in a zip.
            # Keeps original file structure (though this might include parent
            # files, but only this firmware will be contained in it) and keeps
            # original file names.
            logging.debug(
                "Constructing zip for %s version %s", item["name"], item["version"]
            )
            files_store = get_project_settings().get("FILES_STORE")
            file_infos = [
                {"path": files_store + x["path"], "url": x["url"]}
                for _, x in results
                if x
            ]
            logging.debug(file_infos)
            zip_name = self.__create_file_path(
                vendor_name=self.clean_name(item["vendor_name"]),
                name=self.clean_name(item["name"]),
                version=self.clean_name(item["version"]),
                # Changing the name here so the collective zip is in a separate directory
                url_hash="full_directory/" + self.__get_url_hash(item["file_url"]),
                extension=".zip",
            )
            if not os.path.exists(Path(files_store + zip_name)):
                # ZipFile fails if the directory does not yet exist.
                os.mkdir(
                    Path(
                        files_store
                        + self.clean_name(item["vendor_name"])
                        + "/"
                        + self.clean_name(item["name"])
                        + "/"
                        + self.clean_name(item["version"])
                        + "/"
                        + "full_directory/"
                    )
                )
                with ZipFile(files_store + zip_name, mode="w") as zip:
                    for file_info in file_infos:
                        file_path = file_info["path"]
                        url = file_info["url"]
                        filename = PurePosixPath(urllib.parse.urlparse(url).path)
                        zip.write(file_path, arcname=filename)
                        # Not removing the original files, as that will prevent them
                        # from getting redownloaded every time the spider is run again.
                        # This does cause it to be space inefficient.
                        # os.remove(file_path)
            firmware_location = zip_name
            logging.debug("Zip path: %s", firmware_location)
            firmware_checksum = hashlib.md5(
                open(files_store + zip_name, "rb").read()
            ).hexdigest()
        else:
            firmware_checksum = [x["checksum"] for ok, x in results if x][0]
            firmware_location = [x["path"] for ok, x in results if x][0]
        settings = get_project_settings()
        firmware_size = os.path.getsize(settings.get("FILES_STORE") + firmware_location)
        logging.debug(
            """Firmware download information:
                checksum: %s,
                location: %s,
                size: %s""",
            firmware_checksum,
            firmware_location,
            firmware_size,
        )

        # uploading file, getting archive information
        archive_url = None
        if self.UPLOAD_TO_IA:
            archive_url = self.uploader.upload_firmware(
                firmware_item=item,
                firmware_checksum=firmware_checksum,
                firmware_location=firmware_location,
            )
        cursor = self.connection.cursor()
        # check if this firmware already has an entry with the same name,
        # version and vendor. If this is the case, replace metadata with the latest version
        cursor.execute(
            "SELECT * FROM firmware WHERE name = %s AND version = %s AND vendor = %s",
            (item["name"], item["version"], item["vendor_name"]),
        )
        present = cursor.fetchone()

        if present:
            # These fields are user-updated, if they are populated then insert them again.
            # If not they are none, and can be inserted anyways.
            os_field = present["operating_system"]
            architecture = present["architecture"]
            logging.info(
                """
                There is already and existing firmware entry with:
                name: %s
                version: %s
                vendor: %s
                This metadata will be updated.
                """,
                item["name"],
                item["version"],
                item["vendor_name"],
            )

            try:
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE firmware
                        SET
                            name = %s,
                            version = %s,
                            firmware_url = %s,
                            firmware_location = %s,
                            archive_url = %s,
                            firmware_checksum = %s,
                            firmware_size = %s,
                            vendor = %s,
                            cpe_name = %s,
                            operating_system = %s,
                            architecture = %s
                        WHERE id = %s
                        """,
                        (
                            item["name"],
                            item["version"],
                            item["file_url"],
                            firmware_location,
                            archive_url,
                            firmware_checksum,
                            firmware_size,
                            item["vendor_name"],
                            item["cpe_name"],
                            os_field,
                            architecture,
                            # Separation, this is the selection criterium
                            present["id"],
                        ),
                    )

            except BaseException as e:
                logging.error(
                    """
                    %s encountered when updating firmware metadata:
                    name: %s
                    version: %s,
                    cpe_name: %s
                    """,
                    e,
                    item["name"],
                    item["version"],
                    item["cpe_name"],
                )
                self.connection.rollback()
            else:
                self.connection.commit()
        else:
            try:
                with self.connection.cursor() as cursor:
                    # Then reference vendor when inserting vulnerability
                    cursor.execute(
                        """
                        INSERT INTO firmware (
                            name,
                            version,
                            firmware_url,
                            firmware_location,
                            archive_url,
                            firmware_checksum,
                            firmware_size,
                            vendor,
                            cpe_name
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
                        """,
                        (
                            item["name"],
                            item["version"],
                            item["file_url"],
                            firmware_location,
                            archive_url,
                            firmware_checksum,
                            firmware_size,
                            item["vendor_name"],
                            item["cpe_name"],
                        ),
                    )
            except BaseException as e:
                logging.error(
                    """
                    %s encountered when inserting firmware metadata:
                    name: %s
                    version: %s,
                    cpe_name: %s
                    """,
                    e,
                    item["name"],
                    item["version"],
                    item["cpe_name"],
                )
                self.connection.rollback()
            else:
                self.connection.commit()
