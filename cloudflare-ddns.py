import argparse
import requests, json, sys, os
import time


def main():
    path = os.getcwd() + "/"
    version = float(str(sys.version_info[0]) + "." + str(sys.version_info[1]))

    if(version < 3.5):
        raise Exception("This script requires Python 3.5+")

    args = parse_args()

    with open(path + "config.json") as config_file:
        config = json.loads(config_file.read())

    afs = []
    if args.ipv4 or not (args.ipv4 or args.ipv6):
        afs.append('ipv4')
    if args.ipv6 or not (args.ipv4 or args.ipv6):
        afs.append('ipv6')

    if args.repeat:
        print("Updating A & AAAA records every 10 minutes")
        delay = 10*60 # 10 minutes
        updateIPs(config, afs)
        while True:
            time.sleep(delay)
            updateIPs(config, afs)
    else:
        updateIPs(config, afs)


def parse_args():
    parser = argparse.ArgumentParser(description=('Update Cloudflare dynamic '
        'DNS with this host\'s public IP addresses. Update both IPv4 and IPv6 '
        'if no address family is specified.'))

    parser.add_argument('--repeat', action='store_true',
        help='Update every 10 minutes')
    parser.add_argument('-4', dest='ipv4', action='store_true', help='Update IPv4 address')
    parser.add_argument('-6', dest='ipv6', action='store_true', help='Update IPv6 address')
    args = parser.parse_args()
    return args


def updateIPs(config, afs):
    for ip in get_ip_addresses(afs):
        commit_record(ip, config)


def get_ip_addresses(afs):

    af_config = {
        "ipv4": {
            "checker": "https://1.1.1.1/cdn-cgi/trace",
            "type": "A",
        },
        "ipv6": {
            "checker": "https://[2606:4700:4700::1111]/cdn-cgi/trace",
            "type": "AAAA",
        },
    }

    ret = []

    for af in afs:
        config = af_config[af]
        try:
            result = requests.get(config['checker']).text.splitlines()
            ip_address = dict(s.split("=") for s in result)["ip"]
        except requests.exceptions.RequestException:
            print("Warning: could not get {} address".format(af))
        else:

            ret.append({
                "type": config["type"],
                "ip_address": ip_address,
            })

    return ret


def commit_record(ip, config):
    stale_record_ids = []
    for c in config["cloudflare"]:
        subdomains = c["subdomains"]
        response = cf_api("zones/" + c['zone_id'], "GET", c)
        base_domain_name = response["result"]["name"]
        ttl = 120
        if "ttl" in c:
            ttl=c["ttl"]
        for subdomain in subdomains:
            subdomain = subdomain.lower()
            exists = False
            record = {
                "type": ip["type"],
                "name": subdomain,
                "content": ip["ip_address"],
                "proxied": c["proxied"],
                "ttl": ttl
            }
            list = cf_api(
                "zones/" + c['zone_id'] + "/dns_records?per_page=100&type=" + ip["type"], "GET", c)
            
            full_subdomain = base_domain_name
            if subdomain:
                full_subdomain = subdomain + "." + full_subdomain
            
            dns_id = ""
            for r in list["result"]:
                if (r["name"] == full_subdomain):
                    exists = True
                    if (r["content"] != ip["ip_address"]):
                        if (dns_id == ""):
                            dns_id = r["id"]
                        else:
                            stale_record_ids.append(r["id"])
            if(exists == False):
                print("Adding new record " + str(record))
                response = cf_api(
                    "zones/" + c['zone_id'] + "/dns_records", "POST", c, {}, record)
            elif(dns_id != ""):
                # Only update if the record content is different
                print("Updating record " + str(record))
                response = cf_api(
                    "zones/" + c['zone_id'] + "/dns_records/" + dns_id, "PUT", c, {}, record)

    # Delete duplicate, stale records
    for identifier in stale_record_ids:
        print("Deleting stale record " + str(identifier))
        response = cf_api(
            "zones/" + c['zone_id'] + "/dns_records/" + identifier, "DELETE", c)

    return True


def cf_api(endpoint, method, config, headers={}, data=False):
    api_token = config['authentication']['api_token']
    if api_token != '' and api_token != 'api_token_here':
        headers = {
            "Authorization": "Bearer " + api_token,
            **headers
        }
    else:
        headers = {
            "X-Auth-Email": config['authentication']['api_key']['account_email'],
            "X-Auth-Key": config['authentication']['api_key']['api_key'],        
        }

    if(data == False):
        response = requests.request(
            method, "https://api.cloudflare.com/client/v4/" + endpoint, headers=headers)
    else:
        response = requests.request(
            method, "https://api.cloudflare.com/client/v4/" + endpoint, headers=headers, json=data)

    return response.json()


if __name__ == "__main__":
    main()
