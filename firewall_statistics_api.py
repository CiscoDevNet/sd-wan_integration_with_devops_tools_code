from influxdb import InfluxDBClient
import requests
import sys
import json
import os
import pprint
import time
import yaml

requests.packages.urllib3.disable_warnings()

from requests.packages.urllib3.exceptions import InsecureRequestWarning

class Authentication:

    @staticmethod
    def get_jsessionid(vmanage_host, vmanage_port, username, password):
        api = "/j_security_check"
        base_url = "https://%s:%s"%(vmanage_host, vmanage_port)
        url = base_url + api
        payload = {'j_username' : username, 'j_password' : password}
        
        response = requests.post(url=url, data=payload, verify=False)
        try:
            cookies = response.headers["Set-Cookie"]
            jsessionid = cookies.split(";")
            return(jsessionid[0])
        except:
            print("No valid JSESSION ID returned\n")
            exit()
       
    @staticmethod
    def get_token(vmanage_host, vmanage_port, jsessionid):
        headers = {'Cookie': jsessionid}
        base_url = "https://%s:%s"%(vmanage_host, vmanage_port)
        api = "/dataservice/client/token"
        url = base_url + api      
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            return(response.text)
        else:
            return None

if __name__ == '__main__':

    try:

        print("Loading vManage login details from YAML\n")
        with open("vmanage_login.yaml") as f:
            config = yaml.safe_load(f.read())

        vmanage_host = config["vmanage_host"]
        vmanage_port = config["vmanage_port"]
        username = config["vmanage_username"]
        password = config["vmanage_password"]

        Auth = Authentication()
        jsessionid = Auth.get_jsessionid(vmanage_host,vmanage_port,username,password)
        token = Auth.get_token(vmanage_host,vmanage_port,jsessionid)

        if token is not None:
            headers = {'Content-Type': "application/json",'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
        else:
            headers = {'Content-Type': "application/json",'Cookie': jsessionid}

        base_url = "https://%s:%s/dataservice"%(vmanage_host,vmanage_port)

        payload = {
                    "query": {
                        "condition": "AND",
                        "rules": [
                        {
                            "value": [
                            "24"
                            ],
                            "field": "entry_time",
                            "type": "date",
                            "operator": "last_n_hours"
                        },
                        {
                            "value": [
                            "total"
                            ],
                            "field": "type",
                            "type": "string",
                            "operator": "in"
                        }
                        ]
                    },
                    "aggregation": {
                        "metrics": [
                                        {
                                            "property": "fw_total_insp_count",
                                            "type": "sum",
                                            "order": "desc"
                                        }
                                    ],
                        "histogram": {
                                        "property": "entry_time",
                                        "type": "minute",
                                        "interval": 30,
                                        "order": "asc"
                                     }
                    }
                    }

        api_url = "/statistics/fwall/aggregation"

        url = base_url + api_url

        response = requests.post(url=url, headers=headers, data=json.dumps(payload), verify=False)

        if response.status_code == 200:
            items = response.json()['data']
        else:
            print("\nFailed to retrieve Firewall Inspect Session statistics")
            exit()


        # login credentials for InfluxDB

        USER = 'root'
        PASSWORD = 'root'
        DBNAME = 'firewall_inspect'


        host='localhost'
        port=8086

        series = []
        total_records = 0

        json_body = {}

        # loop over the API response variable items and create records to be stored in InfluxDB

        for i in items:
            json_body = {
                        "measurement": "firewall_inspect_count",
                        "tags": {
                                    "host": "wan_edge",
                                },
                        "time": time.strftime('%m/%d/%Y %H:%M:%S',  time.gmtime(i['entry_time']/1000.)),
                        "fields": {
                                    "value": float(i['fw_total_insp_count'])
                        }
                        }
            series.append(json_body)
            total_records = total_records+1

        client = InfluxDBClient(host, port, USER, PASSWORD, DBNAME)

        print("Create a retention policy")
        retention_policy = 'retention_policy_1'
        client.create_retention_policy(retention_policy, '10d', 3, default=True)

        print("Write points #: {0}".format(total_records))
        client.write_points(series, retention_policy=retention_policy)

        time.sleep(2)

    except Exception as e:
        print('Exception line number: {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)