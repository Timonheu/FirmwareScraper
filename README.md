# firmwareScraper

This project is part of a master thesis. A link to the thesis will be posted here soon.

This project consists of scrapers (using Scrapy) that automatically download firmware images and associated metadata, and aims to link this to known vulnerabilities in the National Vulnerability Database. The ultimate aim is to make this dataset useful for testing fuzzers targeting embedded firmware.

Currently contains a scraper deployment in docker (using scrapyd) communicating with a separate dockerized PostgreSQL database. Currently saves firmware metadata to a PostgreSQL database, and links this firmware to a CPE using the NVD. From this CPE matching CVEs are collected and inserted into the same database.

Firmware images are also downloaded, and uploaded to archive.org.

## Environment variables

In a file named `.env` in the root directory the following variables are expected:

- `DATA_PATH`, which contains the path to the location on your host system where you want to save scrapy logs and downloaded firmware. Ensure the user in the docker container has read and write permissions on this directory.
- `NVD_API_KEY`, which contains your key for the NVD API.
- `IA_ACCESS_KEY`, which contains your Internet Archive access key.
- `IA_SECRET_KEY`, which contains your Internet Archive secret key.
- `PGADMIN_DEFAULT_EMAIL`, which contains the e-mail address to use for logging in to pgadmin.
- `UPLOAD_TO_IA`, firmware is only uploaded to the internet archive if this is set to `True` (case insensitive).

The password for the database and pgadmin needs to be present in `db/password.txt`.

Any new environment variables that you want to acces from within the container should be set in `compose.yaml`.

## Usage

Build the containers with docker compose. Once it is up and running, the scrapyd web UI can be reached at http://localhost:6800/.

A spider can be started by running `schedule_spiders.py` **from the host** while the docker containers are running. It is recommended to do this from within a virtual environment with `requirements.txt` installed, as some packages are needed for the function that automatically detects all spiders. (If this does not work, one can use the command seen on the scrapyd web UI.) This script will schedule all scrapers specified through user input one at a time to avoid any possible rate limits. Often the actual downloading and uploading of firmware is the bottleneck anyways.

If you only want to update CPE and CVE entries of existing firmware in the database with new information from the NVD, you can run `update_cpes_cves.py` **from within the scrapyd container**. This will prompt you to specify for which vendors you want to look for new CPEs, and whether you want to update all CVE data. Note that this can take a while, as it is heavy on communication with the NVD API.

### Database

The database can be interacted with through pgadmin at http://localhost:5050 when the containers are running. For the credentials needed for logging in, see [Environment variables](#environment-variables). For more information about using pgadmin, see the documentation: https://www.pgadmin.org/docs/pgadmin4/8.5/.

A relationship entity diagram of the database design can be found in `database-layout.pdf`. A diagram can also be generated in pgadmin.

A backup with all collected data can be found in the `db` directory, and can be restored through the pgadmin user interface.

To connect the database, click on Add New Server. Write a suitable name in the name field (like `firmwareScraper`). Connection details are (in the Connection tab):

- Host name/address: `database`

- Port: `5432`

- Maintenance database: `metadata`

- Username: `postgres`

- Password: The password present in `db/password.txt` (see [Environment variables](#environment-variables))

Save the password and hit Save. This connection and any changed settings should persist between deployments, as it is saved in a Docker volume.

*This is an old workflow from before the pgadmin container existed, but it still works:* the PostgreSQL database can be backed up manually by running `database_backup.sh` while the database container is running. This runs `pg_dump` on the metadata database, and saves it to a folder in `DATA_PATH` (see [Environment variables](#environment-variables)).

### Firmware Architecture Detection

There is a script, `arch_detect.py`, that attempts to automatically detect the processor architecture the firmware was designed for (only architecture, like ARM or MIPS, no specific versions like ARMv7 (yet)), the operating system family (currently only Linux or Windows), endianness and whether it is 32 or 64 bits. When run *from within* the container, this script will attempt to unpack and analyze one version of the firmware for each device that has `NULL` in the 'architecture` column.

It will look for parseable binaries, and put the found data in the `architecture` table. Logging will occur in `ArchDetect.log` found in `DATA_PATH` (see [Environment variables](#environment-variables)).

It is possible that `lief.parse()` hangs. At the time of writing I have not found a workaround, as that function probably contains a bare except. That means a (custom) timeoutexception will get caught in that function, meaning I was unable to implement a timeout.

## Development

For details on how Scrapy works, I recommend consulting the scrapy documentation: https://docs.scrapy.org/en/2.11/index.html

### Project specific spider development details

Each spider should extend the `FirmwareScraperSpider` class. This is to ensure it can interface with the `schedule_spiders.py` and `update_cpes_cves.py` scripts. This parent class also provides a function for CPE collection required by `update_cpes_cves.py`, see [the CPE section](#cpe-and-cve-collection) for details.

Each spider **must** have the following attributes:

- `name`: The name by which the spider can be called directly.

- `vendor_name`: The name of the vendor. This name must also be yielded in the `vendor_name` field of the `firmwareScraperItem` described below.

- `vendor_url`: The url of the vendor website. This value is used in the database.

- `cpe_vendor_names`: A list of vendor spellings that may be used in the vendor field of relevant CPEs. Some vendors can have ambiguous way to spell them, and these spellings may be used interchangeably. For example, if Secura was a vendor, possible spellings might be `secura`, `secura-bv`, `securabv`. It is best to manually search for relevant CPEs to know which spellings would be effective.

The scraper should yield valid `firmwareScraperItem` instances which have the following populated fields:

- `name`: The name of the firmware. Is generally the name of the device model.

- `version`: A string that signifies the version of the firmware.
  
  - Note: This field is also used as a directory name for the downloaded firmware, so keep in mind this should be unique per individual piece of firmware. Special characters for file paths (`/`.`/`, `.`,`..`,`:` and `;`) will automatically be replaced before using it as a directory name.

- `file_urls`: A list of urls from which files will be downloaded. Use this if multiple files should be downloaded. If this field is set, `file_url` will be ignored when downloading, but this url will be inserted into the database as the download url. All files downloaded will be combined into a single .zip before it is uploaded to the internet archive.

- `file_url`: The url from which the pipeline will download the actual firmware. If `file_urls` is set the value in this field is still inserted in the database, and it is still used for generating a file name.

- `vendor_name`: Name of the vendor, this should always be `self.vendor_name`, to ensure it is properly linked to the vendor table in the database.

- `cpe_name`: The `cpe_name` field of the corresponding `CPEItem`. See [the CPE section](#cpe-and-cve-collection) for details.

### Internet Archive

The process for uploading firmware to the Internet Archive can be toggled with the variable `UPLOAD_TO_IA` (see [Environment variables](#environment-variables)). 

The upload collection is currently set to `embeddedfirmware`, this is the collection I have access to. This can be changed by changing the variable `self.collection_name` in `__init__()` of `internet_archive_uploader.py`. If you do not have access to any internet archive collections, I recommend setting the collection to `open_source_software`, as this is the community software collection everybody has access to.

All firmware in the database for which the field `archive_url` is not set can automatically be updated with the script `update_archive.py` when it is run from within the container. This will attempt to upload all firmware that have `NULL` in `archive_url` to the internet archive if it is not there yet and insert the archive.org URL in the database. This process is logged in the directory specified in `DATA_PATH` (see [Environment variables](#environment-variables)) in the file `archiveUpdate.log`.

#### CPE and CVE collection

The basic way of collecting a CPE corresponding to your firmware item is by calling `self.getCPE` with as a parameter `data`, a dict with the following fields:

- `name`: The name of the firmware. This will be used to query the NVD for CPEs matching that name.

- `vendor`: The name of the vendor. If the vendor field in a CPE does not match this string, that CPE will be discarded. For vendors with ambiguous names it might be worthwhile to call this function multiple times, once for each possible vendor spelling.

- `version`: The version of the firmware. If the version field in a CPE is not empty and does not match this string, that CPE will be discarded.

This function simply calls `NVDRequester.getCPE`.

For some vendors this implementation is not sufficient, e.g. for TP-Link. For these cases more information is provided [here](#special-cpe-collection). However, when overriding `getCPE`, ensure that the function is called **the exact same way**. This is expected by the script `update_cpes_cves.py`.

When a cpe item has been collected, and is called i.e. `cpe`, It is recommended to include the following code snippet **before** yielding the corresponding firmware item:

```python
if cpe["cpe_name"] is not None:
    yield cpe
    requester = nvdrequester.NVDRequester()
    for vulnerability in requester.get_CVE_items(cpe["cpe_name"]):
        yield vulnerability
```

This ensures the corresponding CVEs are collected, and that everything is inserted into the database in the correct order.

If you want to allow multiple firmwares of a vendor to have the same CPE (this was necessary for TP-Link for example), include the `vendor_name` in the list `DO_NOT_DEDUPLICATE_CPES` in `pipelines.py`.

##### Special CPE collection

There is a possibility for a special case of CPE collection which was created specifically to deal with the versioning of TP-link, which caused very inconsistent CPEs. The following two fields of `NVDRequester.getCPE` are optional, and should be used in tandem:

- `secondary_version=""`
  
  - Allows for a secondary version string, which can signify i.e. a sub-version, which might be present in the version or update field of the CPE. Currently only used when `version_contain` is set to `True` (see below).

- `version_contain=False`
  
  - When set to True, instead of checking whether `version` exactly matches the version field of the CPE, a more relaxed check is done: whether both `version` and `secondary_version` are a substring in either the version or update field of the CPE.
