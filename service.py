#!/usr/bin/python3

import sys
import os
import argparse
from progress.spinner import Spinner
from termcolor import colored
import json

from masc.constants import LOGS_DIR, BACKUPS_DIR
from masc.custom import Custom
from masc.wordpress import Wordpress
from masc.drupal import Drupal
from masc.print_utils import print_green, print_blue, print_red, print_info, print_results
from masc.dictionary import Dictionary
from masc.masc_utils import MascUtils





def handler():
    name = 'no-name'
    site_type = 'wordpress'
    path = '/var/www/kazlc'
    all_malware_file = {}
    malware_file = []

    old_stdout = sys.stdout # backup current stdout
    sys.stdout = open(os.devnull, "w")

    cms = Wordpress(path, name)
   
    Dictionary.load_suspect_files(site_type, path)
    Dictionary.load_suspect_content(site_type, path)
    Dictionary.load_signatures()

    cms.scan()

    sys.stdout = old_stdout # reset old stdout

    files_to_remove = cms.compare_with_clean_installation()

    if len(files_to_remove) == 0:
        print("No malware")

    if len(files_to_remove) > 0:
        #print_red("Malware/suspect files were found. They will be removed if you include the option --clean-site")
        for filename in files_to_remove:
            malware_file.append(os.path.join(cms.path, filename))
        all_malware_file['Malware Files'] = malware_file
        enablePrint()
        return json.dumps(all_malware_file)

    exit()