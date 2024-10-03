import internetarchive

from firmwareScraper.items import FirmwareScraperItem
from scrapy.utils.project import get_project_settings

# from items import FirmwareScraperItem
import re
import os
import logging


class InternetArchiveUploader:
    def __init__(self):
        # TODO: document this
        self.collection_name = "embeddedfirmware"
        ACCESS_KEY = os.environ.get("IA_ACCESS_KEY")
        if not ACCESS_KEY:
            logging.error("Environment variable IA_ACCESS_KEY is set incorrectly.")
        SECRET_KEY = os.environ.get("IA_SECRET_KEY")
        if not SECRET_KEY:
            logging.error("Environment variable IA_SECRET_KEY is set incorrectly.")
        self.config = {
            "s3": {"access": ACCESS_KEY, "secret": SECRET_KEY},
            "logging": {"level": "DEBUG", "file": "/data/internet_archive.log"},
        }
        self.session = internetarchive.get_session(config=self.config)

    # Returns the url to the uploaded item
    def upload_firmware(
        self,
        firmware_item: FirmwareScraperItem,
        firmware_checksum: str,
        firmware_location: str,
    ):
        identifier = self.__prepare_identifier(
            firmware_item["vendor_name"]
            + "_"
            + firmware_item["name"]
            + "_"
            + firmware_item["version"]
            + "_"
            + firmware_checksum[:5]
        )
        url = "https://archive.org/download/" + identifier

        # Test whether the archive item already exists
        item = self.session.get_item(identifier)
        if not item.identifier_available():
            logging.warning(
                """
                The identifier already exists on archive.org:
                Identifier: %s
                No firmware will be uploaded.
                """,
                identifier,
            )
            return url

        title = firmware_item["name"] + " firmware version " + firmware_item["version"]
        metadata = {
            "collection": self.collection_name,
            "title": title,
            "mediatype": "software",
            "creator": firmware_item["vendor_name"],
            "subject": "embedded firmware",
        }
        file_path = get_project_settings().get("FILES_STORE") + firmware_location
        extension = self.__get_file_extension(firmware_location)
        remote_file_name = firmware_checksum + extension

        logging.debug(
            """
            Will upload the following file to the internet archive:
            location: %s
            remote file name: %s
            identifier: %s
            metadata: %s
            """,
            file_path,
            remote_file_name,
            identifier,
            metadata,
        )

        response = item.upload(files={remote_file_name: file_path}, metadata=metadata)
        # TODO: make more robust
        response[0].raise_for_status()

        logging.debug("Upload succesful. Archive url: %s", url)
        return url

    # Removes all characters from string that are not allowed in an
    # internet archive identifier.
    # Only alphanumeric characters, '_' '-' and '.' are allowed.
    def __prepare_identifier(self, string):
        forbidden_characters = re.compile(r"[^a-zA-Z0-9\._\-]+")
        # TODO: ensure the identifier is under 100 characters
        return re.sub(forbidden_characters, "", string)

    # Takes as input a file path, returns the file extension used in this path
    def __get_file_extension(self, string):
        extension_match = re.compile(r"\.[0-9a-zA-Z]+$")
        return re.search(extension_match, string).group()

    def test(self):
        assert self.__prepare_identifier("NPort IA5000A-I/O") == "NPortIA5000A-IO"
        assert self.__prepare_identifier("NPort_IA5000A-I-O") == "NPort_IA5000A-I-O"
        assert (
            self.__prepare_identifier(
                "ln*)(&*#_()&%%lknfsinf3o98nflxknv  segf;nifgfn9lskdfn~!@$!#%@$&^"
            )
            == "ln_lknfsinf3o98nflxknvsegfnifgfn9lskdfn"
        )

        assert self.__get_file_extension("bnolie/lianbvibg/lsdfni.txt") == ".txt"
        assert (
            self.__get_file_extension("D-Link/DAP-1820-US/1.11.01/12800e8917.zip")
            == ".zip"
        )
        assert (
            self.__get_file_extension("Moxa/NPort IA5000A-I&O/2.0/e385bbb58a.rom")
            == ".rom"
        )
        assert (
            self.__get_file_extension("D-Link/DAP-1820-US/1.11.01/12800e8917.ZIP")
            == ".ZIP"
        )
        print("all tests passed")


# test = InternetArchiveUploader("test")
# test.test()
