import os
import json
import yara

from masc.constants import BASE_PATH
from masc.print_utils import print_red, print_blue
from progress.bar import Bar
from termcolor import colored

DICTS_PATH = os.path.join(BASE_PATH, "dicts/")
SIGNATURES_PATH = os.path.join(BASE_PATH, "signatures/")

SUSPECT_FILES_DATA = "_suspect_files.data"
SUSPECT_CONTENT_DATA = "_suspect_content.data"
CHECKSUM_PATH = SIGNATURES_PATH + "checksum/"
RULES_PATH = SIGNATURES_PATH + "rules/"


class Dictionary:
    """This class represents the dictionary that manage signatures and rules databases"""
    suspect_files = []
    suspect_content = []
    signatures_db = {}
    yara_rules = []

    @classmethod
    def load_suspect_files(cls, type, path):
        """Return suspect files for an specified type of installation: wordpress, joomla . . ."""
        with open(os.path.join(DICTS_PATH, type + SUSPECT_FILES_DATA)) as file:
            for line in file:
                if line.startswith("#"):
                    continue
                cls.suspect_files.append(path + line.rstrip())

    @classmethod
    def load_suspect_content(cls, type, path):
        with open(os.path.join(DICTS_PATH, type + SUSPECT_CONTENT_DATA)) as file:
            for line in file:
                if line.startswith("#"):
                    continue
                cls.suspect_content.append(line.rstrip())

    @classmethod
    def load_signatures(cls):
        """Load signatures (checksums and YARA rules) to create the signatures dictionary"""
        errors = False

        signatures_count = len(list(os.scandir(CHECKSUM_PATH)))
        bar = Bar(colored("Loading malware signature files", "blue"), fill=colored("#", "blue"),
                  max=signatures_count, suffix='%(percent)d%%')
        # Load malware signatures
        for entry in os.scandir(CHECKSUM_PATH):
            file_data = open(entry.path).read()
            signatures = json.loads(file_data)

            for signature_hash in signatures["Database_Hash"]:
                cls.signatures_db[signature_hash["Malware_Hash"]] = signature_hash["Malware_Name"]

            bar.next()

        bar.finish()
        print_blue("Loaded " + str(len(cls.signatures_db)) + " malware signatures")

        rules_count = len(list(os.scandir(RULES_PATH)))
        bar = Bar(colored("Loading YARA rules . . .", "blue"), fill=colored("#", "blue"),
                  max=rules_count, suffix='%(percent)d%%')
        # Load YARA rules
        for entry in os.scandir(RULES_PATH):
            try:
                rules = yara.compile(filepath=entry.path)
                cls.yara_rules.append(rules)
            except Exception:
                errors = True

            bar.next()

        bar.finish()
        if errors:
            print_red("Some errors while reading yara rules. Some rules were not loaded")

        print_blue("Loaded " + str(len(cls.yara_rules)) + " YARA rules")

    @staticmethod
    def download_hashes():
        pass

    @staticmethod
    def download_yara_rules():
        pass

    @staticmethod
    def add_suspect_file(type, filename):
        """Add a suspect file to the masc dictionary"""
        with open(os.path.join(DICTS_PATH, type + SUSPECT_FILES_DATA), "a+") as file:
            file.write(filename + "\n")

    @staticmethod
    def add_suspect_content(type, content):
        """Add a suspect content to the masc dictionary"""
        with open(os.path.join(DICTS_PATH, type + SUSPECT_CONTENT_DATA), "a+") as file:
            file.write(content + "\n")
