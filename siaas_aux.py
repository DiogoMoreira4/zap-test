# Intelligent System for Automation of Security Audits (SIAAS)
# Agent - Auxiliary functions
# By João Pedro Seara, 2023

import ipaddress
import scapy.config
import scapy.layers.l2
import scapy.route
import scapy.utils
import math
import dns.resolver
import pprint
import logging
import uuid
import os
import sys
import re
import requests
import urllib3
import json
from datetime import datetime

logger = logging.getLogger(__name__)


def merge_module_dicts(modules=""):
    """
    Grabs all local DBs (dicts) from the module list and concatenates them
    Returns False if it fails
    """
    merged_dict = {}
    for module in sorted(set(modules.lower().split(','))):
        next_dict_to_merge = {}
        module = module.strip()
        try:
            module_dict = read_from_local_file(
                os.path.join(sys.path[0], 'var/'+str(module)+'.db'))
            if module_dict != None:
                next_dict_to_merge[module] = module_dict
                merged_dict = dict(
                    list(merged_dict.items())+list(next_dict_to_merge.items()))
        except:
            logger.error("Couldn't merge dict: " +
                         str(next_dict_to_merge))
            return False

    return merged_dict


def merge_configs_from_upstream(local_dict=os.path.join(sys.path[0], 'var/config_local.db'), output=os.path.join(sys.path[0], 'var/config.db'), upstream_dict=None):
    """
    Merges the upstream configs to the local configs, after removing protected configurations from the upstream configs
    If the config disappears from the server, it reverts to the local config
    In case of errors, no changes are made, and False is returned
    """

    if upstream_dict == None:
        upstream_dict = {}

    local_config_dict = {}
    merged_config_dict = {}
    delta_dict = {}
    protected_configs = ["log_level", "api_uri", "api_user", "api_pwd",
                         "api_ssl_ignore_verify", "api_ssl_ca_bundle", "enable_internal_api", "offline_mode"]
    try:
        local_config_dict = get_config_from_configs_db(local_dict=local_dict)
        if type(upstream_dict) is not dict:
            raise TypeError("Upstream configs are invalid.")
        for p in protected_configs:  # remove any protected configs from upstream dict
            for k in upstream_dict.copy().keys():
                if p.lower().strip() == k.lower().strip():
                    del(upstream_dict[k])
        if len(upstream_dict) > 0:
            merged_config_dict = dict(
                list(local_config_dict.items())+list(upstream_dict.items()))
            logger.debug(
                "The following configurations are being applied/overwritten from the server: "+str(upstream_dict))
        else:
            merged_config_dict = dict(
                list(local_config_dict.items()))
            logger.debug(
                "No configurations were found in the upstream dict. Using local configurations only.")
    except:
        logger.error(
            "Could not merge configurations from the upstream dict. Not doing any changes.")
        return False

    return write_to_local_file(output, dict(sorted(merged_config_dict.items(), key=lambda x: x[0].casefold() if len(x or "") > 0 else None)))


def get_request_to_server(api_uri, ignore_ssl=False, ca_bundle=None, api_user=None, api_pwd=None):
    """
    Sends an API GET request and returns the data in a JSON format
    """
    urllib3.disable_warnings()
    if ignore_ssl == True:
        logger.warning(
            "SSL verification is off! This might have security implications while connecting to the server API.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        r = requests.get(api_uri, timeout=60, verify=verify,
                         allow_redirects=True, auth=(api_user, api_pwd))
    except Exception as e:
        logger.error(
            "Error while performing a GET request to the server API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the server API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
        return r.json()
    else:
        logger.error("Error getting data from the server API: " +
                     str(r.status_code))
        return False


def post_request_to_server(api_uri, data_to_post, ignore_ssl=False, ca_bundle=None, api_user=None, api_pwd=None):
    """
    Sends a data dict to the API via a POST request
    """
    urllib3.disable_warnings()
    if ignore_ssl == True:
        logger.warning(
            "SSL verification is off! This might have security implications while connecting to the server API.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        r = requests.post(api_uri, json=data_to_post, timeout=60,
                          verify=verify, allow_redirects=True, auth=(api_user, api_pwd))
    except Exception as e:
        logger.error(
            "Error while performing a POST request to the server API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was written to the server API:\n" +
                     pprint.pformat(data_to_post, sort_dicts=False))
        return True
    else:
        logger.error("Error posting data to the server API: " +
                     str(r.status_code))
        return False


def get_config_from_configs_db(local_dict=os.path.join(sys.path[0], 'var/config.db'), config_name=None, convert_to_string=True):
    """
    Reads a configuration value from the configs db
    If the intput is "None" it returns an entire dict with all the values. Returns an empty dict if there are no configs
    If the input is a specific config key, it returns the value for that config key. Returns None if the config key does not exist
    """
    if config_name == None:

        logger.debug("Getting configuration dictionary from local DB ...")
        config_dict = read_from_local_file(
            local_dict)
        if not isinstance(config_dict, dict):
            logger.error(
                "Configuration dictionary from the local DB is not in a valid format. Returning nothing.")
            return {}
        if len(config_dict or '') > 0:
            out_dict = {}
            for k in config_dict.keys():
                if convert_to_string:
                    out_dict[k] = str(config_dict[k])
                else:
                    out_dict[k] = config_dict[k]
            return config_dict

        logger.error("Couldn't get configuration dictionary from local DB.")
        return {}

    else:

        logger.debug("Getting configuration value '" +
                     config_name+"' from local DB ...")
        config_dict = read_from_local_file(
            local_dict)
        if not isinstance(config_dict, dict):
            logger.error(
                "Configuration dictionary from the local DB is not in a valid format. Returning nothing.")
            return None
        if len(config_dict or '') > 0:
            if config_name in config_dict.keys():
                value = config_dict[config_name]
                if convert_to_string:
                    value = str(value)
                return value

        logger.debug("Couldn't get configuration named '" +
                     config_name+"' from local DB. Maybe it doesn't exist.")
        return None


def write_config_db_from_conf_file(conf_file=os.path.join(sys.path[0], 'conf/siaas_agent.cnf'), output=os.path.join(sys.path[0], 'var/config.db')):
    """
    Writes the configuration  (dict) from the config file. If the file is empty or does not exist, returns False
    It will strip all characters after '#', and then strip the spaces from the beginning or end of the resulting string. If the resulting string is empty, it will ignore it
    Then, it will grab the string before the first "=" as the config key, and after it as the actual value
    The config key has its spaces removed from beginning or end, and all " and ' are removed
    The actual value is just stripped of spaces from the beginning and the end
    Writes the resulting dict in the  file of config.db. This means it will return True if things go fine, or False if it fails
    """

    logger.debug("Writing configuration local DB, from local file: "+conf_file)

    config_dict = {}

    local_conf_file = read_from_local_file(conf_file)
    if len(local_conf_file or '') == 0:
        return False

    for line in local_conf_file.splitlines():
        try:
            line_uncommented = line.split('#')[0].strip()
            if len(line_uncommented) == 0:
                continue
            config_name = line_uncommented.split("=", 1)[0].strip()
            if not validate_string_key(config_name):
                raise ValueError("Invalid character in config key.")
            config_value = line_uncommented.split("=", 1)[1].strip()
            config_dict[config_name] = config_value
        except:
            logger.warning(
                "Invalid line from local configuration file was ignored: "+str(line))
            continue

    return write_to_local_file(output, dict(sorted(config_dict.items(), key=lambda x: x[0].casefold() if len(x or "") > 0 else None)))


def write_to_local_file(file_to_write, data_to_insert):
    """
    Writes data (usually a dict) to a local file, after converting it to a JSON format
    Returns True if all went OK
    Returns False if it failed
    """
    logger.debug("Inserting data to local file "+file_to_write+" ...")
    try:
        os.makedirs(os.path.dirname(os.path.join(
            sys.path[0], file_to_write)), exist_ok=True)
        logger.debug("All data that will now be written to the file:\n" +
                     pprint.pformat(data_to_insert, sort_dicts=False))
        with open(file_to_write, 'w') as file:
            file.write(json.dumps(data_to_insert, sort_keys=False))
            logger.debug("Local file write ended successfully.")
            return True
    except Exception as e:
        logger.error(
            "There was an error while writing to the local file "+file_to_write+": "+str(e))
        return False


def read_from_local_file(file_to_read):
    """
    Reads data from local file and returns it
    It will return None if it failed
    """
    logger.debug("Reading from local file "+file_to_read+" ...")
    try:
        with open(file_to_read, 'r') as file:
            content = file.read()
            try:
                content = eval(content)
            except:
                pass
            return content
    except Exception as e:
        logger.error("There was an error while reading from local file " +
                     file_to_read+": "+str(e))
        return None


def get_or_create_unique_system_id():
    """
    Reads the local UID file and returns it
    If this file does not exist or has no data, tries to generate an UID. If it has an invalid UID, it will return a nil UID
    Proceeds to try to generate an UID from local system data
    If this fails, generates a random one
    If all fails, returns a nil UID
    """
    logger.debug(
        "Searching for an existing UID and creating a new one if it doesn't exist ...")
    try:
        with open(os.path.join(sys.path[0], 'var/uid'), 'r') as file:
            content = file.read()
            if len(content or '') == 0:
                raise IOError(
                    "Nothing valid could be read from local UID file.")
            if content.split('\n')[0] == "ffffffff-ffff-ffff-ffff-ffffffffffff":
                logger.warning(
                    "Invalid ID, reserved for broadcast. Returning a nil UID.")
                return "00000000-0000-0000-0000-000000000000"
            logger.debug("Reusing existing UID: "+str(content))
            return content.split('\n')[0].lower()
    except:
        pass
    logger.debug(
        "Existing UID not found. Creating a new one from system info ...")
    new_uid = ""
    try:
        with open("/sys/firmware/devicetree/base/serial-number", 'r') as file:  # Raspberry Pi serial
            content = file.read()
            new_uid = str(content.split('\n')[0].strip().strip('\x00'))
    except:
        pass
    if len(new_uid or '') < 5:  # minimum number of characters, to avoid DB duplication
        try:
            with open("/sys/class/dmi/id/board_serial", 'r') as file:
                content = file.read()
                new_uid = str(content.split('\n')[0].strip().strip('\x00'))
        except:
            pass
    if len(new_uid or '') < 5:
        try:
            with open("/sys/class/dmi/id/product_uuid", 'r') as file:
                content = file.read()
                new_uid = str(content.split('\n')[0].strip().strip('\x00'))
        except:
            pass
    if len(new_uid or '') < 5:
        try:
            with open("/var/lib/dbus/machine-id", 'r') as file:
                content = file.read()
                new_uid = str(content.split('\n')[0].strip().strip('\x00'))
        except:
            pass
    if len(new_uid or '') < 5:
        logger.warning(
            "Couldn't create a new UID from the system info. Will create a new randomized UID for this session only!")
        try:
            new_uid = "temp-"+str(uuid.UUID(int=uuid.getnode()))
        except:
            logger.error(
                "There was an error while generating a new UID. Returning a nil UID.")
            return "00000000-0000-0000-0000-000000000000"
    try:
        os.makedirs(os.path.join(sys.path[0], 'var'), exist_ok=True)
        with open(os.path.join(sys.path[0], 'var/uid'), 'w') as file:
            file.write(new_uid)
            logger.debug("Wrote new UID to a local file: "+new_uid)
    except Exception as e:
        logger.error("There was an error while writing to the local UID file: " +
                     str(e) + ". Returning a nil UID.")
        return "00000000-0000-0000-0000-000000000000"
    return new_uid.lower()


def validate_bool_string(input_string, default_output=False):
    """
    Validates string format and if it's not empty and returns a boolean
    """
    if type(default_output) is not bool:
        return None
    if default_output == False:
        if len(input_string or '') > 0:
            if input_string.lower() == "true":
                return True
        return False
    if default_output == True:
        if len(input_string or '') > 0:
            if input_string.lower() == "false":
                return False
        return True


def validate_string_key(string):
    """
    Validates the proper format of a string configuration key and returns a boolean
    """
    pattern = "^[A-Za-z0-9_-]*$"
    if type(string) is not str:
        logger.debug(
            "This data dict has a key which is not a string. No data was uploaded.")
        return False
    if len(string or '') == 0:
        logger.debug(
            "This data dict has an empty or invalid key. No data was uploaded.")
        return False
    if not bool(re.match(pattern, string)):
        logger.debug(
            "Invalid character detected in data dict keys. No data was uploaded.")
        return False
    return True


def get_size(size_bytes, suffix="B"):
    """
    Scale bytes to a shorter "MB" or "GB" format
    Example: 1253656678 -> 1.17GB
    """
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if size_bytes < factor:
            return f"{size_bytes:.2f} {unit}{suffix}"
        size_bytes /= factor


def convert_sec_to_pretty_format(seconds):
    """
    Converts a number of seconds to a pretty day/hr/min/sec format
    """
    time = float(seconds)
    day = time // (24 * 3600)
    time = time % (24 * 3600)
    hour = time // 3600
    time %= 3600
    mins = time // 60
    time %= 60
    secs = time
    if day != 0:
        return "%d day %d hr %d min %d sec" % (day, hour, mins, secs)
    if hour != 0:
        return "%d hr %d min %d sec" % (hour, mins, secs)
    if mins != 0:
        return "%d min %d sec" % (mins, secs)
    else:
        return "%d sec" % (secs)


def get_now_utc_str():
    """
    Returns an ISO date string
    """
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


def get_now_utc_obj():
    """
    Returns an ISO date object
    """
    return datetime.strptime(datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'), '%Y-%m-%dT%H:%M:%SZ')


def ip_sorter(s):
    """
    IP sorter to use in sorted function
    """
    try:
        ip = int(ipaddress.ip_address(s))
    except ValueError:
        return (1, s)
    return (0, ip)


def sort_ip_dict(ip_dict):
    """
    Sorts a dict by their keys considering they're IPs
    """
    out_dict = {}
    try:
        sorted_keys = sorted(ip_dict.keys(), key=ip_sorter)
        for k in sorted_keys:
            out_dict[k] = ip_dict[k]
    except:
        pass
    return out_dict


def is_ipv4_or_ipv6(ip):
    """
    Returns "6" if input IP is IPv6
    Returns "4" if input IP is IPv4
    Else returns None
    """
    try:
        ipaddress.IPv4Network(ip)
        return "4"
    except:
        pass
    try:
        ipaddress.IPv6Network(ip)
        return "6"
    except:
        return None


def get_ipv6_cidr(mask):
    """
    Returns the IPv6 short netmask from a long netmask input
    Returns None if inputted mask is not proper
    """
    bit_count = [0, 0x8000, 0xc000, 0xe000, 0xf000, 0xf800, 0xfc00, 0xfe00,
                 0xff00, 0xff80, 0xffc0, 0xffe0, 0xfff0, 0xfff8, 0xfffc, 0xfffe, 0xffff]
    count = 0
    try:
        for w in mask.split(':'):
            if not w or int(w, 16) == 0:
                break
            count += bit_count.index(int(w, 16))
    except:
        logger.warning("Bad IPv6 netmask: "+mask)
        return None
    return count


def get_all_ips_for_name(host):
    """
    Checks all registered DNS IPs for a said host and returns them in a set
    If the input is already an IP address, returns it
    Returns an empty set if no IPs are found 
    """
    ips = []

    # If it's localhost return right away
    if str(host) == "localhost":
        ips.append("127.0.0.1")
        return ips

    # Check if the host is already an IP and return it
    try:
        ipaddress.IPv4Network(host)
        ips.append(host)
        return ips
    except:
        pass
    try:
        ipaddress.IPv6Network(host)
        ips.append(host)
        return ips
    except:
        pass

    # IPv4 name resolution
    try:
        result = dns.resolver.resolve(host, "A")
        for ipval in result:
            if ipval.to_text() not in ips:
                ips.append(ipval.to_text())
    except:
        pass

    # IPv6 name resolution
    try:
        result6 = dns.resolver.resolve(host, "AAAA")
        for ipval in result6:
            if ipval.to_text() not in ips:
                ips.append(ipval.to_text())
    except:
        pass

    return sorted(ips, key=ip_sorter)


def long2net(arg):
    """
    Converts an hexadecimal IPv4 netmask to a 0-32 integer
    """
    if (arg <= 0 or arg >= 0xFFFFFFFF):
        raise ValueError("Illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_cidr_notation(bytes_network, bytes_netmask):
    """
    Converts a network and network mask inputs in bytes to a network/short_mask IPv4 CIDR notation
    """
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network, netmask)
    return net
