import logging
from firmwareScraper import items
import psycopg


# File that contains functions for inserting and/or updating CPE and CVE entries in the database.
# These are in a separate file so they can be invoked separately without initializing the pipeline.
def cpe_insertion(item: items.CPEItem, connection: psycopg.Connection):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM cpe WHERE cpe_name = %s", (item["cpe_name"],))
    present = cursor.fetchone()
    if present:
        logging.info(
            """
                There is already and existing cpe entry with:
                cpe_name: %s
                This vendor data will not be inserted.
                """,
            item["cpe_name"],
        )
    else:
        try:
            with connection.cursor() as cursor:
                # Then reference vendor when inserting vulnerability
                cursor.execute(
                    """
                        INSERT INTO cpe (
                            cpe_name,
                            cpe_name_id
                        ) VALUES (%s, %s);
                        """,
                    (item["cpe_name"], item["cpe_name_id"]),
                )
        except BaseException as e:
            logging.error(
                "%s encountered when inserting cpe name %s", e, item["cpe_name"]
            )
            connection.rollback()
        else:
            connection.commit()


def cve_insertion_update(item: items.CVEItem, connection: psycopg.Connection):
    cursor = connection.cursor()
    # Check if there is already an entry for this CVE
    cursor.execute(
        "SELECT * FROM vulnerability WHERE cve_id = %s",
        (item["cve_id"],),
    )
    present = cursor.fetchone()
    if present:
        logging.info(
            """
            There is already and existing vulnerability entry with:
            cve_id: %s
            This cve entry will be updated.
            """,
            item["cve_id"],
        )

        # collect data that could have been input manually
        level_of_knowledge = present["level_of_knowledge"]
        vulnerable_protocols = present["vulnerable_protocols"]
        vulnerable_files = present["vulnerable_files"]
        stack_trace = present["stack_trace"]
        vulnerable_files = present["vulnerable_files"]
        further_notes = present["further_notes"]
        # update firmware entry
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE vulnerability
                    SET
                        description = %s,
                        cve_references = %s,
                        vendor_comments = %s,
                        level_of_knowledge = %s,
                        vulnerable_protocols = %s,
                        vulnerable_files = %s,
                        stack_trace = %s,
                        binary_offset = %s,
                        further_notes = %s
                    WHERE
                        cve_id = %s
                    """,
                    (
                        item["description"],
                        item["references"],
                        item["vendor_comments"],
                        level_of_knowledge,
                        vulnerable_protocols,
                        vulnerable_files,
                        stack_trace,
                        vulnerable_files,
                        further_notes,
                        # separation, this is the selection criterium
                        item["cve_id"],
                    ),
                )
        except BaseException as e:
            logging.error(
                """
                %s encountered when updating vulnerability data:
                cve_id: %s
                cpe_name: %s
                """,
                e,
                item["cve_id"],
                item["cpe_name"],
            )
            connection.rollback()
        else:
            connection.commit()
    else:
        # Insert vulnerability data
        try:
            logging.debug("Inserting %s into database", item["cve_id"])
            cursor.execute(
                """
                INSERT INTO vulnerability (
                    cve_id,
                    description,
                    cve_references,
                    vendor_comments
                ) VALUES (%s, %s, %s, %s);
                """,
                (
                    item["cve_id"],
                    item["description"],
                    item["references"],
                    item["vendor_comments"],
                ),
            )
        except BaseException as e:
            logging.error(
                """
                %s encountered when inserting vulnerability data:
                cve_id: %s
                cpe_name: %s
                description: %s
                references: %s
                vendor_comments: %s
                """,
                e,
                item["cve_id"],
                item["cpe_name"],
                item["description"],
                item["references"],
                item["vendor_comments"],
            )
            connection.rollback()
        else:
            connection.commit()
    try:
        # insert cwe data
        for cwe in item["cwe_items"]:
            cursor = connection.cursor()
            cursor.execute(
                "SELECT * FROM weakness WHERE cwe_id = %s",
                (cwe["cwe_id"],),
            )
            present = cursor.fetchone()
            logging.debug("cwe %s query result: %s", cwe["cwe_id"], present)
            if not present:
                logging.debug("Inserting cwe")
                cursor.execute(
                    "INSERT INTO weakness (cwe_id) VALUES (%s)",
                    (cwe["cwe_id"],),
                )
            # assumes data from NVD is well formed
            if cwe["source_type"] is not None:
                source_type = "p" if cwe["source_type"] == "Primary" else "s"
            else:
                source_type = None
            # check whether this vulnerability and weakness already have a link
            cursor = connection.cursor()
            cursor.execute(
                "SELECT * FROM vulnerability_weakness WHERE cve_id = %s AND cwe_id = %s",
                (item["cve_id"], cwe["cwe_id"]),
            )
            if cursor.fetchone():
                logging.info(
                    "There is already an existing link between %s and %s, so this will not be reinserted.",
                    item["cve_id"],
                    cwe["cwe_id"],
                )
            else:
                logging.debug(
                    "inserting link between %s and %s",
                    item["cve_id"],
                    cwe["cwe_id"],
                )
                cursor.execute(
                    """
                    INSERT INTO vulnerability_weakness (
                        cve_id,
                        cwe_id,
                        source,
                        source_type
                    ) VALUES (%s, %s, %s, %s);
                    """,
                    (
                        item["cve_id"],
                        cwe["cwe_id"],
                        cwe["source"],
                        source_type,
                    ),
                )
    except BaseException as e:
        logging.error(
            """
            %s encountered when inserting cwe data:
            cwe_id: %s
            cve_id: %s
            """,
            e,
            cwe["cwe_id"],
            item["cve_id"],
        )
        connection.rollback()
    else:
        connection.commit()

    # link vulnerability to cpe
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT * FROM vulnerability_firmware WHERE
        cve_id = %s AND cpe_name = %s;
        """,
        (item["cve_id"], item["cpe_name"]),
    )
    present = cursor.fetchone()
    if present:
        logging.debug(
            """
            CVE %s and CPE %s already have an existing link.
            This link will not be reinserted.
            """,
            item["cve_id"],
            item["cpe_name"],
        )
    else:
        try:
            cursor.execute(
                """
                INSERT INTO vulnerability_firmware (
                    cve_id,
                    cpe_name
                ) VALUES (%s, %s);
                """,
                (item["cve_id"], item["cpe_name"]),
            )
        except BaseException as e:
            logging.error(
                "%s occurred when inserting the link betweeen %s and %s",
                e,
                item["cve_id"],
                item["cpe_name"],
            )
            connection.rollback()
        else:
            connection.commit()
