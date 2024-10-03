import psycopg
from firmwareScraper import database_insertions
from firmwareScraper import nvdrequester
import get_spiders
import shlex
import sys

# This script will see if any new CPEs have been created
# for firmware in the database, and insert them into the
# database have. It then inserts CVEs for newly added CPEs.
# It can also update all CVE data and looks for new CVEs.


update_cpes_input = ""
while update_cpes_input not in ["y", "yes", "n", "no"]:
    update_cpes_input = input("Do you wish to search for new CPEs? y/n\t").lower()
update_cpes = update_cpes_input == "y" or update_cpes_input == "yes"

if update_cpes:
    valid_spiders = get_spiders.get_spiders()
    valid_spider_names = [x.vendor_name.lower() for x in valid_spiders]

    print("Valid spiders:")
    for spider in valid_spiders:
        print("\t- " + spider.vendor_name)

    to_schedule = input(
        "\nPlease enter all the names of the vendors for which you want to search for new CPEs separated by spaces. Spider names can be quoted. Or input the word 'all' to schedule all spiders.\n"
    ).lower()

    input_list = shlex.split(to_schedule)
    spiders = []
    for vendor in input_list:
        if vendor not in valid_spider_names:
            if vendor == "all":
                spiders = valid_spiders
                break
            else:
                print(vendor + " is not a valid spider name, exiting.")
                sys.exit("Invalid spider name provided.")
        else:
            spiders.append([x for x in valid_spiders if x.vendor_name == vendor][0])

    print(
        f"Updating data for the following vendors: {[x.vendor_name for x in spiders]}"
    )

update_cves_input = ""
while update_cves_input not in ["y", "yes", "n", "no"]:
    update_cves_input = input("Do you wish to update all CVE data? y/n\t").lower()
update_cves = update_cves_input == "y" or update_cves_input == "yes"

if not (update_cves or update_cpes):
    sys.exit("Nothing to do.")


# connection details
hostname = "db"
username = "postgres"
password = open("db/password.txt", "r").read()
database = "metadata"

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


# Reusable function for inserting CVEs.
def __cve_insertion(cpe_name):
    for cve in nvdrequester.NVDRequester().get_CVE_items(cpe_name):
        print(f"Inserting {cve['cve_id']} for {cve['cpe_name']}")
        database_insertions.cve_insertion_update(cve, connection)


# for each vendor, do the following:
# - Collect all firmware images with no associated CPE
# - Retry matching a CPE
# - insert found CPEs using the pipeline function
if update_cpes:
    for spider in spiders:
        vendor_names = spider.cpe_vendor_names
        with connection.cursor() as cursor:
            firmwares = connection.execute(
                """
                SELECT * FROM firmware WHERE vendor = %s AND cpe_name is NULL
                """,
                (spider.vendor_name,),
            )
        print(f"Checking {firmwares.rowcount} firmware rows from {spider.vendor_name}.")
        for firmware in firmwares:
            name = firmware["name"]
            version = firmware["version"]
            for vendor_name in vendor_names:
                cpe = spider().getCPE(
                    {"name": name, "version": version, "vendor": vendor_name}
                )
                if cpe["cpe_name"]:
                    print(f"Found a cpe for {name} version {version}:")
                    print(cpe["cpe_name"])
                    database_insertions.cpe_insertion(cpe, connection)
                    __cve_insertion(cpe["cpe_name"])
                else:
                    print(f"No CPE found for {name} version {version}.")

# for each cpe, do the following:
# - Retry collecting CVEs
# - insert/update found CVEs using the pipeline function
if update_cves:
    with connection.cursor() as cursor:
        cpes = connection.execute("SELECT * FROM cpe")
    print(f"Checking {cpes.rowcount} CPEs for associated vulnerabilities.")
    for cpe in cpes:
        __cve_insertion(cpe["cpe_name"])
