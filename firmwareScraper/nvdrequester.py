import requests
import re
import time
import os
import logging
import random
from difflib import SequenceMatcher
from firmwareScraper.items import CVEItem, CWEItem, CPEItem
from psycopg.types.json import Jsonb


class NVDRequester:
    def __init__(self):
        self.API_KEY = os.environ.get("NVD_API_KEY")
        if not self.API_KEY:
            logging.error("environment variable NVD_API_KEY is set incorrectly.")

    # Returns all CVEs that are applicable to the provided CPE as a list of CVE items.
    def get_CVE_items(self, cpe_name):
        api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"apiKey": self.API_KEY}
        parameters = {"cpeName": cpe_name, "noRejected": None, "isVulnerable": None}
        pages = self.__api_requests(api_url, parameters, headers)
        vulnerabilities = []
        # Combine pages
        for page in pages:
            for vulnerability in page["vulnerabilities"]:
                vulnerabilities.append(vulnerability)
        vulnerability_items = []
        # convert to items
        for vulnerability in vulnerabilities:
            cve = vulnerability["cve"]
            vuln_item = CVEItem()
            vuln_item["cve_id"] = cve["id"]
            # Get the english description
            if "descriptions" in cve:
                vuln_item["description"] = next(
                    (
                        desc["value"]
                        for desc in cve["descriptions"]
                        if desc["lang"] == "en"
                    ),
                    None,
                )
            else:
                vuln_item["description"] = None
            if "references" in cve:
                vuln_item["references"] = [
                    Jsonb(reference) for reference in cve["references"]
                ]
            else:
                vuln_item["references"] = None
            vuln_item["vendor_comments"] = (
                cve["vendorComments"] if "vendorComments" in cve else None
            )
            vuln_item["cpe_name"] = cpe_name
            vuln_item["cwe_items"] = []
            if "weaknesses" in cve:
                for weakness in cve["weaknesses"]:
                    weakness_item = CWEItem()
                    # get the value of the english description
                    weakness_item["cwe_id"] = next(
                        (
                            desc
                            for desc in weakness["description"]
                            if desc["lang"] == "en"
                        ),
                        None,
                    )["value"]
                    weakness_item["source"] = weakness["source"]
                    weakness_item["source_type"] = weakness["type"]
                    vuln_item["cwe_items"].append(weakness_item)
            vulnerability_items.append(vuln_item)
        return vulnerability_items

    # data is a dict with a "name", "vendor" and "version" field
    # version_contain is for a special and more lenient filtering on
    # version developed for tp-link CPEs, this is also what secondary_version is for.
    # secondary_version can be an empty string.
    # returns a CPEItem
    def getCPE(self, data, version_contain=False, secondary_version=""):
        api_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
        # If the vendor is included in keywords, returns all CPEs of that vendor
        keywords = [data["name"]]
        headers = {"apiKey": self.API_KEY}
        parameters = {"keywordSearch": keywords}

        pages = self.__api_requests(api_url, parameters, headers)
        products = {"products": []}
        # combine pages
        for page in pages:
            for product in page["products"]:
                products["products"].append(product)

        # filter results
        products["products"] = [
            entry
            for entry in products["products"]
            if not self.__should_be_filtered(
                entry, data, version_contain, secondary_version
            )
        ]

        if len(products["products"]) == 0:
            item = CPEItem()
            item["cpe_name"] = None
            item["cpe_name_id"] = None
            return item

        cpe = self.pick_best_cpe(products, data)

        # Insert version number if not present
        # find all escaped colons
        cpeName = cpe["cpeName"]
        escaped_colons = [m.start() for m in re.finditer(r"\\:", cpeName)]
        # remove all escaped colons
        prepared_cpeName = cpeName.replace("\:", "")
        cpe_list = prepared_cpeName.split(":")
        if cpe_list[5] == "*" or cpe_list[5] == "-":
            # insert version
            cpe_list[5] = data["version"]
        # put the string back to gether
        cpeName = ":".join(cpe_list)
        # put all the escaped colons back
        for colon in escaped_colons:
            cpeName = cpeName[:colon] + "\:" + cpeName[colon:]

        item = CPEItem()
        item["cpe_name"] = cpeName
        item["cpe_name_id"] = cpe["cpeNameId"]
        return item

    # TODO: make more robust and exhaustive
    def __should_be_filtered(self, entry, data, version_contain, secondary_version):
        cpe = entry["cpe"]
        # check if the CPE is deprecated
        if cpe["deprecated"]:
            return True
        # check if the CPE is from the right vendor (and the right CPE version)
        vendor = data["vendor"]
        vendor_re = re.compile(r"cpe:2\.3:[a-z]:" + vendor + ":.*")
        if vendor_re.fullmatch(cpe["cpeName"]) is None:
            return True

        if not version_contain:
            if not NVDRequester.cpeVersionMatch(data["version"], cpe["cpeName"]):
                return True
        else:
            if not NVDRequester.cpeVersionContain(
                data["version"], cpe["cpeName"], secondary_version
            ):
                return True

        # filter out hardware CPEs
        hardware_re = re.compile(r"cpe:2\.3:h:.*")
        if hardware_re.fullmatch(cpe["cpeName"]) is not None:
            return True

        return False

    # Returns true if the cpeName exactly matches the version, or if the cpeName does not
    # have a specified version. Assumes the version does not contain a colon.
    def cpeVersionMatch(version, cpeName):
        # remove escaped colons
        prepared_cpeName = cpeName.replace("\:", "")
        version_substring = prepared_cpeName.split(":")[5]
        if (
            version_substring == "*"
            or version_substring == "-"
            or version_substring == version.lower()
        ):
            return True
        else:
            return False

    # Returns true of the cpeName contains the version and secondary_version in the version or update
    # field, or if the cpeName does not have a specified version. Assumes the version does not contain
    # a colon
    def cpeVersionContain(version, cpeName, secondary_version):
        # remove escaped colons
        prepared_cpeName = cpeName.replace("\:", "")
        split_cpe = prepared_cpeName.split(":")
        version_substring = split_cpe[5]
        update_substring = split_cpe[6]
        # version is in either the version_substring or update_substring
        primary_contain = (
            version.lower() in version_substring or version.lower() in update_substring
        )
        # secondary_version is in either the version_substring or update_substring
        # automatically holds if secondary_version is the empty string
        secondary_contain = (
            secondary_version.lower() in version_substring
            or secondary_version.lower() in update_substring
        )
        if (
            version_substring == "*"
            or version_substring == "-"
            or (primary_contain and secondary_contain)
        ):
            return True
        else:
            return False

    # Picks the best CPE from the response and returns it.
    # expects response_json to contain at least 1 cpe
    def pick_best_cpe(self, json_response, data):
        if len(json_response["products"]) == 1:
            return json_response["products"][0]["cpe"]
        else:
            logging.debug("Picking best cpe for %s", data["name"])
            max_match = 0
            best_cpe = None
            for product in json_response["products"]:
                cpeName = product["cpe"]["cpeName"]
                prepared_cpeName = cpeName.replace("\:", "")
                product_substring = prepared_cpeName.split(":")[4]
                match = SequenceMatcher(
                    isjunk=lambda x: x in "\\",
                    a=product_substring,
                    b=data["name"].lower(),
                ).ratio()
                if match > max_match:
                    max_match = match
                    best_cpe = {
                        "cpeName": cpeName,
                        "cpeNameId": product["cpe"]["cpeNameId"],
                    }
            if best_cpe is None:
                logging.error(
                    """
                    Best cpe is None from 
                    response: %s
                    data: %s
                    """,
                    json_response["products"],
                    data,
                )
            logging.debug("best cpe for %s is %s", data["name"], best_cpe["cpeName"])
            return best_cpe

    def __api_requests(self, api_url, parameters, headers):
        # Multiple requests if requests do not fit on one page
        index = 0
        pages = []
        loop = True
        while loop:
            while True:
                response = requests.get(api_url, params=parameters, headers=headers)
                try:
                    response.raise_for_status()
                # This solves all HTTP errors encountered so far
                # TODO: make more robust
                except requests.exceptions.HTTPError as e:
                    timeout = random.randint(
                        2, 10
                    )  # timeout of 2 to 10 seconds (including)
                    logging.warning(
                        """
                        HTTP Error encountered when requesting for %s:
                        %s
                        url: %s
                        trying again after %s seconds""",
                        parameters,
                        e,
                        api_url,
                        timeout,
                    )
                    time.sleep(timeout)
                else:
                    response_json = response.json()
                    pages.append(response_json)
                    if (
                        response_json["totalResults"]
                        > response_json["startIndex"] + response_json["resultsPerPage"]
                    ):
                        index += response_json["resultsPerPage"]
                        parameters["startIndex"] = index
                    else:
                        # break out of the loop for requesting the next page
                        loop = False

                    # break out of the HTTP error checking loop
                    break
        return pages
