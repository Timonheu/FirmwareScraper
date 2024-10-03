import logging
import psycopg
from firmwareScraper import internet_archive_uploader
from firmwareScraper.items import FirmwareScraperItem

logging.basicConfig(filename="/data/ArchiveUpdate.log", level=logging.DEBUG)

# connection details
hostname = "db"
username = "postgres"
password = open("db/password.txt", "r").read()
database = "metadata"


# The upload_firmware function expects a firmware item with these three fields
def create_item(firmware):
    result = FirmwareScraperItem()

    result["vendor_name"] = firmware["vendor"]
    result["name"] = firmware["name"]
    result["version"] = firmware["version"]
    return result


# string passed as argument to start a connection with our db
connection_params = (
    "host="
    + hostname
    + " user="
    + username
    + " password="
    + password
    + " dbname="
    + database
)
connection = psycopg.connect(connection_params, row_factory=psycopg.rows.dict_row)
uploader = internet_archive_uploader.InternetArchiveUploader()
with connection.cursor() as cursor:
    cursor.execute(
        """
        SELECT * FROM firmware
            WHERE archive_url IS NULL
        """
    )
    i = 0
    firmware_list = cursor.fetchall()
    length = len(firmware_list)
    for firmware in firmware_list:
        logging.info("Uploading firmware %s", firmware["name"])
        i += 1
        logging.info("Firmware %s of %s", i, length)
        archive_url = uploader.upload_firmware(
            create_item(firmware),
            firmware["firmware_checksum"],
            firmware["firmware_location"],
        )
        logging.info("Inserting %s for firmware %s", archive_url, firmware["name"])

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE firmware
                        SET archive_url = %s
                        WHERE id = %s
                    """,
                    (archive_url, firmware["id"]),
                )
        except BaseException as e:
            logging.error(
                "%s encountered when inserting archive url %s for firmware %s",
                e,
                archive_url,
                firmware["id"],
            )
            connection.rollback()
        else:
            connection.commit()
