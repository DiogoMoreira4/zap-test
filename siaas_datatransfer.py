# Intelligent System for Automation of Security Audits (SIAAS)
# Agent - Data Transfer module
# By João Pedro Seara, 2023

import siaas_aux
import logging
import os
import sys
import pprint
import time

logger = logging.getLogger(__name__)


def upload_agent_data(api_base_uri, last_uploaded_dict=None, ignore_ssl=False, ca_bundle=None, api_user=None, api_pwd=None, silent=False, first_run=False):
    """
    Uploads agent data (with passwords anonymized), after connecting to the server's API
    If silent mode is on, or first run, only uploads configs and platform data
    Returns True if all OK; False if anything failed
    """

    if last_uploaded_dict == None:
        last_uploaded_dict = {}

    logger.info("Uploading agent data to the server ...")

    siaas_uid = siaas_aux.get_or_create_unique_system_id()

    all_modules = "platform,neighborhood,portscanner,config,zaproxy"

    if silent or first_run:
        modules_to_send = "platform,config"
    else:
        modules_to_send = all_modules

    current_dict_temp = siaas_aux.merge_module_dicts(modules_to_send)

    # create empty keys if they are not in the dict (we want to avoid miss keys in order to keep API consistency on the server side)
    current_dict = {}
    if modules_to_send != all_modules:
        for m in sorted(all_modules.lower().split(',')):
            if m in current_dict_temp.keys():
                current_dict[m] = current_dict_temp[m]
            else:
                current_dict[m] = {}
    else:
        current_dict = current_dict_temp

    try:  # anonymize passwords before sending them
        for k in current_dict["config"].keys():
            if k.endswith("_pwd") or k.endswith("_passwd") or k.endswith("_password"):
                current_dict["config"][k] = '*' * 8
    except:
        pass

    # if (str(current_dict) == str(last_uploaded_dict)) or len(current_dict) == 0:
    #    logger.info(
    #        "No changes were detected in local databases, so there's nothing to upload to the remote DB server. Will check again later ...")
    #    return last_uploaded_dict

    if not siaas_aux.post_request_to_server(api_base_uri+"/siaas-server/agents/data/"+siaas_uid, dict(current_dict), ignore_ssl=ignore_ssl, ca_bundle=ca_bundle, api_user=api_user, api_pwd=api_pwd):
        logger.error(
            "There was a failure while uploading agent data (maybe the server is down or unreachable?).")
        return last_uploaded_dict

    logger.info("Agent data upload to the server finished.")
    return current_dict


def download_agent_configs(api_base_uri, ignore_ssl=False, ca_bundle=None, api_user=None, api_pwd=None):
    """
    Downloads agent configs and merges with local configs
    Returns True if all OK; False if anything failed
    """
    logger.info("Downloading agent configs from the server ...")

    siaas_uid = siaas_aux.get_or_create_unique_system_id()

    downloaded_configs_raw = siaas_aux.get_request_to_server(
        api_base_uri+"/siaas-server/agents/configs/"+siaas_uid+"?merge_broadcast=1", ignore_ssl=ignore_ssl, ca_bundle=ca_bundle, api_user=api_user, api_pwd=api_pwd)

    if type(downloaded_configs_raw) == bool and downloaded_configs_raw == False:
        logger.error(
            "There was a failure while downloading agent configs (maybe the server is down or unreachable?). The current configuration is kept.")
        return False

    try:
        # check if a configuration dict for this uid was received
        downloaded_configs = downloaded_configs_raw["output"][siaas_uid]
    except:
        downloaded_configs = {}

    if siaas_aux.merge_configs_from_upstream(upstream_dict=downloaded_configs):
        logger.info("Agent configs download finished and merged locally.")
        return True
    else:
        logger.error("There was an error merging downloaded agent configs.")
        return False


def loop():
    """
    Data Transfer module loop (calls the download and upload functions)
    """
    last_uploaded_dict = {}
    last_downloaded_dict = {}

    # Generate global variables from the configuration file
    config_dict = siaas_aux.get_config_from_configs_db(convert_to_string=True)
    API_URI = None
    API_USER = None
    API_PWD = None
    API_SSL_IGNORE_VERIFY = None
    API_SSL_CA_BUNDLE = None
    for config_name in config_dict.keys():
        if config_name.upper() == "API_URI":
            API_URI = config_dict[config_name]
        if config_name.upper() == "API_USER":
            API_USER = config_dict[config_name]
        if config_name.upper() == "API_PWD":
            API_PWD = config_dict[config_name]
        if config_name.upper() == "API_SSL_IGNORE_VERIFY":
            API_SSL_IGNORE_VERIFY = config_dict[config_name]
        if config_name.upper() == "API_SSL_CA_BUNDLE":
            API_SSL_CA_BUNDLE = config_dict[config_name]

    ssl_ignore_verify = siaas_aux.validate_bool_string(API_SSL_IGNORE_VERIFY)

    ssl_ca_bundle = None
    if len(API_SSL_CA_BUNDLE or '') > 0:
        ssl_ca_bundle = os.path.join(sys.path[0], API_SSL_CA_BUNDLE)

    api_user = None
    api_pwd = None
    if len(API_USER or '') > 0 and len(API_PWD or '') > 0:
        api_user = API_USER
        api_pwd = API_PWD

    valid_api = True
    if len(API_URI or '') == 0:
        logger.error(
            "The API URI is empty. No communications with the server will take place.")
        valid_api = False

    offline_mode = siaas_aux.get_config_from_configs_db(
        config_name="offline_mode", convert_to_string=True)
    no_comms = siaas_aux.validate_bool_string(offline_mode)
    if no_comms:
        logger.warning(
            "Offline mode is on! No data will be transferred to or from the server. If you want to change this behavior, change the local configuration file and restart the application.")

    first_run = True
    while valid_api and not no_comms:

        logger.debug("Loop running ...")

        # Download agent configs
        download_agent_configs(API_URI, ssl_ignore_verify,
                               ssl_ca_bundle, api_user, api_pwd)

        time.sleep(3)  # avoid flooding the API

        # Upload agent data
        silent_mode = siaas_aux.get_config_from_configs_db(
            config_name="silent_mode", convert_to_string=True)
        silent = siaas_aux.validate_bool_string(silent_mode)
        if silent:
            logger.warning(
                "Silent mode is on! This means only config-related data is being sent to the server.")
        last_uploaded_dict = upload_agent_data(API_URI,
                                               last_uploaded_dict, ssl_ignore_verify, ssl_ca_bundle, api_user, api_pwd, silent, first_run)

        first_run = False

        # Sleep before next loop
        try:
            sleep_time = int(siaas_aux.get_config_from_configs_db(
                config_name="datatransfer_loop_interval_sec"))
            logger.debug("Sleeping for "+str(sleep_time) +
                         " seconds before next loop ...")
            time.sleep(sleep_time)
        except:
            logger.debug(
                "The interval loop time is not configured or is invalid. Sleeping now for 1 hour by default ...")
            time.sleep(3600)


if __name__ == "__main__":

    log_level = logging.INFO
    logging.basicConfig(
        format='%(asctime)s %(levelname)-5s %(filename)s [%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=log_level)

    if os.geteuid() != 0:
        print("You need to be root to run this script!", file=sys.stderr)
        sys.exit(1)

    print('\nThis script is being directly run, so it will just read data from the DB!\n')

    siaas_uid = siaas_aux.get_or_create_unique_system_id()
    # siaas_uid = "00000000-0000-0000-0000-000000000000" # hack to show data from all agents

    api_base_uri = "https://siaas/api"

    pprint.pprint(siaas_aux.get_request_to_server(
        api_base_uri+"/siaas-server/agents/configs/"+siaas_uid+"?merge_broadcast=1", ignore_ssl=True, api_user="siaas", api_pwd="siaas"), sort_dicts=False)

    print('\nAll done. Bye!\n')
