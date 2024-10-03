import logging
import psycopg
import lief
import os
import shlex
import shutil
import subprocess
from pathlib import Path
import tempfile


def parse_elf_arch(filepath):
    header = (
        lief.ELF.parse(str(filepath)).header if lief.ELF.parse(str(filepath)) else None
    )
    if not header:
        return None
    arch = header.machine_type
    return arch.__name__.split(".")[-1]


def parse_pe_arch(filepath):
    header = (
        lief.PE.parse(str(filepath)).header if lief.PE.parse(str(filepath)) else None
    )
    if not header:
        return None
    arch = header.machine_type
    return arch.__name__.split(".")[-1]


logging.basicConfig(filename="/data/ArchDectect.log", level=logging.DEBUG)

firmware_path_string = "/data/firmware/"

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

with connection.cursor() as cursor:
    # Select only the first occurrence of every name vendor combination
    cursor.execute(
        """
            WITH CTE AS (
                SELECT
                    *,
                    ROW_NUMBER() OVER (PARTITION BY name, vendor ORDER BY id) as rn
                FROM firmware
            )
            SELECT *
            FROM CTE
            WHERE rn = 1 AND architecture is NULL;
        """
    )
    i = 0
    firmware_list = cursor.fetchall()
    length = len(firmware_list)
    for firmware in firmware_list:
        logging.info(
            "Commencing architecture detection for firmware %s", firmware["name"]
        )
        i += 1
        logging.info("Firmware image %s of %s", i, length)
        location = Path(firmware_path_string + firmware["firmware_location"])

        results = dict()

        extension = firmware["firmware_location"].split(".")[-1]

        with tempfile.TemporaryDirectory(
            dir=os.path.split(location)[0], ignore_cleanup_errors=True
        ) as working_directory_name:
            working_directory = Path(working_directory_name)
            logging.debug("Working directory: %s", working_directory)

            ignored_files = [
                "digest",
                "txt",
                "md",
                "pdf",
                "doc",
                "docx",
            ]
            logging.info("Attempting to unpack %s", str(location))
            extension = str(location).lower().split(".")[-1]
            if extension in ignored_files:
                logging.info("Ignoring this file due to its extension")
                continue

            unblob_command = shlex.split(
                shutil.which("unblob")
                + " '"
                + str(location)
                + "' --extract-dir '"
                + str(working_directory)
                + "'"
            )
            unblob_process = subprocess.Popen(
                unblob_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            timeout = 180
            topdown = False
            try:
                (out, err) = unblob_process.communicate(timeout=timeout)
                if err:
                    logging.info("Unblob encountered an error: %s", err)
                else:
                    # logging.info("Unblob output:")
                    # logging.info(out)
                    logging.info("Unblob encountered no fatal errors.")
            except subprocess.TimeoutExpired:
                unblob_process.kill()
                logging.info(
                    "Unblob took longer than %s seconds, killed the process.", timeout
                )
                # If timeout expired, walk topdown
                topdown = True

            logging.debug(
                "looking for binary in the directory %s", str(working_directory)
            )

            unpacked = False

            for root, dirs, files in os.walk(working_directory):
                print(f"Searching {len(files)} files")
                for name in files:
                    os_family = "unknown"
                    arch = None
                    endianness = None
                    bits = None

                    file_path = os.path.join(root, name)

                    # This may cause LIEF to hang
                    try:
                        if os.path.getsize(file_path) <= 0:
                            continue
                    except FileNotFoundError:
                        pass
                    binary = lief.parse(file_path)
                    if binary:
                        if str(binary.format).endswith("ELF"):
                            # logging.debug("Found ELF at %s", str(file_path))
                            os_family = "Linux"
                        elif str(binary.format).endswith("PE"):
                            # logging.debug("Found PE at %s", str(file_path))
                            os_family = "Microsoft Windows"
                        if binary.abstract.header.is_32:
                            bits = 32
                        elif binary.abstract.header.is_64:
                            bits = 64
                        endianness = (
                            str(binary.abstract.header.endianness)
                            .split(".")[-1]
                            .lower()[0]
                        )
                        # Architecture is sometimes NONE
                        arch = str(binary.abstract.header.architecture).split(".")[-1]
                        if arch == "NONE":
                            arch = None

                        if arch:
                            key = "@".join((os_family, arch, str(bits), endianness))
                            if key not in results:
                                results[key] = 0
                            results[key] = results[key] + 1

            total_binaries = 0
            most_binaries = 0
            most_binaries_key = None
            logging.info("Results: %s", results)
            for key in results:
                total_binaries += results[key]
                if results[key] > most_binaries:
                    most_binaries = results[key]
                    most_binaries_key = key

            # If one OS architecture combination comprises at least 66% of all parsable binaries
            # we are certain we found the architecture
            if most_binaries_key and most_binaries >= total_binaries * 0.66:
                # Parse result back from key
                split_key = most_binaries_key.split("@")
                os_family = split_key[0]
                arch = split_key[1]
                bits = int(split_key[2])
                endianness = split_key[3]

                unpacked = True
                logging.info(
                    """
                    Found the following information:
                        Operating System Family: %s
                        Architecture: %s
                        %s bits
                        %s endian

                    This architecture was found in %s of %s parsable binaries.
                    """,
                    os_family,
                    arch,
                    bits,
                    endianness,
                    most_binaries,
                    total_binaries,
                )

            else:
                os_family = "unknown"
                arch = None
                bits = None
                endianness = None
                arch = "unknown"
                if most_binaries_key:
                    logging.info(
                        "Most prevalent architecture was %s, but it was only found in %s of %s parsable binaries",
                        most_binaries_key,
                        most_binaries,
                        total_binaries,
                    )
                else:
                    logging.info("No architecture found.")

        if not arch:
            arch = "unknown"
            logging.info("No architecture found.")

        # Update all firmware rows with the same vendor name combination

        with connection.cursor() as cursor:
            if arch != "unknown":
                cursor.execute(
                    """
                    SELECT id FROM architecture
                    WHERE
                        name = %s
                        AND bits = %s
                        AND endianness = %s
                    """,
                    (
                        arch,
                        bits,
                        endianness,
                    ),
                )
                architecture_present = cursor.fetchone()
            else:
                cursor.execute(
                    """
                    SELECT id FROM architecture
                    WHERE
                        name = %s
                        AND bits IS NULL
                        AND endianness IS NULL
                    """,
                    (arch,),
                )
                architecture_present = cursor.fetchone()

            if not architecture_present:
                try:
                    cursor.execute(
                        """
                        INSERT INTO architecture (
                            name,
                            bits,
                            endianness
                        ) VALUES (%s, %s, %s);
                        """,
                        (arch, bits, endianness),
                    )
                except BaseException as e:
                    logging.error(
                        "%s encountered when inserting architecture %s, %s bits endianness %s",
                        e,
                        arch,
                        bits,
                        endianness,
                    )
                    connection.rollback()
                else:
                    connection.commit()
                if arch != "unknown":
                    cursor.execute(
                        """
                        SELECT id FROM architecture
                        WHERE
                            name = %s
                            AND bits = %s
                            AND endianness = %s
                        """,
                        (
                            arch,
                            bits,
                            endianness,
                        ),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT id FROM architecture
                        WHERE
                            name = %s
                            AND bits is NULL
                            AND endianness is NULL
                        """,
                        (arch,),
                    )
                architecture_id = cursor.fetchone()

            else:
                architecture_id = architecture_present
            try:
                cursor.execute(
                    """
                    UPDATE firmware
                    SET
                        architecture = %s,
                        unpacked = %s
                    WHERE
                        name = %s AND vendor = %s
                    """,
                    (
                        architecture_id["id"],
                        unpacked,
                        firmware["name"],
                        firmware["vendor"],
                    ),
                )
            except BaseException as e:
                logging.error(
                    "%s encountered when adding architecture %s to firmware %s",
                    e,
                    architecture_id,
                    firmware["name"],
                )
                connection.rollback()
            else:
                connection.commit()

        # OS family insertion
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id FROM operating_system
                WHERE
                    family_name = %s
                    AND os_name = 'unknown'
                    AND os_version = 'unknown'
                """,
                (os_family,),
            )
            os_family_present = cursor.fetchone()
            if not os_family_present:
                try:
                    cursor.execute(
                        """
                        INSERT INTO operating_system (
                            family_name,
                            os_name,
                            os_version
                        ) VALUES (%s, 'unknown', 'unknown');
                        """,
                        (os_family,),
                    )
                except BaseException as e:
                    logging.error(
                        "%s encountered when inserting os family %s", e, os_family
                    )
                    connection.rollback()
                else:
                    connection.commit()
                cursor.execute(
                    """
                SELECT id FROM operating_system
                WHERE
                    family_name = %s
                    AND os_name = 'unknown'
                    AND os_version = 'unknown'
                """,
                    (os_family,),
                )
                os_family_id = cursor.fetchone()
            else:
                os_family_id = os_family_present
            try:
                cursor.execute(
                    """
                    UPDATE firmware
                    SET
                        operating_system = %s
                    WHERE
                        name = %s AND vendor = %s
                    """,
                    (os_family_id["id"], firmware["name"], firmware["vendor"]),
                )
            except BaseException as e:
                logging.error(
                    "%s encountered when adding os family %s to firmware %s",
                    e,
                    os_family_id,
                    firmware["name"],
                )
                connection.rollback()
            else:
                connection.commit()
