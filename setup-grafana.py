import requests
import json

url = "http://localhost:3000/api/auth/keys"

payload =  { 
             "name": "APIkeysetup",  
             "role": "Admin"
           }

headers = {
            'Content-Type': "application/json",
            'Authorization': "Basic YWRtaW46YWRtaW4=",
          }

response = requests.request("POST", url, data=json.dumps(payload), headers=headers)

if response.status_code == 200:
    api_key = response.json()["key"]
    print("\nCreated API key")
else:
    print("Failed to create API key")
    exit()
    
url = "http://localhost:3000/api/datasources"

payload = {
            "name": "Approute",
            "type": "influxdb",
            "access": "proxy",
            "isDefault": True,
            "password": "admin",
            "user": "admin",
            "basicAuth": True,
            "basicAuthUser": "admin",
            "basicAuthPassword": "admin",
            "jsonData": {
                            "keepCookies": []
                        },
            "secureJsonFields": {
                                    "basicAuthPassword": True
                                },
            "database": "approute_stats",
            "url": "http://localhost:8086",
            "readOnly": False,
            "withCredentials": False
         }


headers = {
            'Content-Type': "application/json",
            'Authorization': "Bearer " + api_key,
          }

response = requests.request("POST", url, data=json.dumps(payload), headers=headers)

if response.status_code == 200:
    print("Added InfluxDB as a datasource")
else:
    print("Failed to add datasource")
    exit()

url = "http://localhost:3000/api/dashboards/import"

true = True
false = False
null = None

payload = {
            "dashboard": {
                "annotations": {
                "list": [
                    {
                    "builtIn": 1,
                    "datasource": "-- Grafana --",
                    "enable": true,
                    "hide": true,
                    "iconColor": "rgba(0, 211, 255, 1)",
                    "name": "Annotations & Alerts",
                    "showIn": 0,
                    "type": "dashboard"
                    }
                ]
                },
                "editable": true,
                "gnetId": null,
                "graphTooltip": 0,
                "id": null,
                "links": [],
                "panels": [
                {
                    "aliasColors": {},
                    "bars": false,
                    "dashLength": 10,
                    "dashes": false,
                    "datasource": "Approute",
                    "decimals": 2,
                    "fieldConfig": {
                    "defaults": {
                        "custom": {}
                    },
                    "overrides": []
                    },
                    "fill": 1,
                    "fillGradient": 0,
                    "gridPos": {
                    "h": 9,
                    "w": 12,
                    "x": 0,
                    "y": 0
                    },
                    "hiddenSeries": false,
                    "id": 2,
                    "legend": {
                    "avg": false,
                    "current": false,
                    "max": false,
                    "min": false,
                    "show": true,
                    "total": false,
                    "values": false
                    },
                    "lines": true,
                    "linewidth": 1,
                    "nullPointMode": "null",
                    "options": {
                    "dataLinks": []
                    },
                    "percentage": false,
                    "pointradius": 2,
                    "points": false,
                    "renderer": "flot",
                    "seriesOverrides": [],
                    "spaceLength": 10,
                    "stack": false,
                    "steppedLine": false,
                    "targets": [
                    {
                        "groupBy": [
                        {
                            "params": [
                            "$__interval"
                            ],
                            "type": "time"
                        },
                        {
                            "params": [
                            "Tunnel"
                            ],
                            "type": "tag"
                        }
                        ],
                        "measurement": "approute_stats",
                        "orderByTime": "ASC",
                        "policy": "default",
                        "refId": "A",
                        "resultFormat": "time_series",
                        "select": [
                        [
                            {
                            "params": [
                                "latency"
                            ],
                            "type": "field"
                            },
                            {
                            "params": [],
                            "type": "distinct"
                            }
                        ]
                        ],
                        "tags": []
                    }
                    ],
                    "thresholds": [],
                    "timeFrom": null,
                    "timeRegions": [],
                    "timeShift": null,
                    "title": "Latency",
                    "tooltip": {
                    "shared": true,
                    "sort": 0,
                    "value_type": "individual"
                    },
                    "type": "graph",
                    "xaxis": {
                    "buckets": null,
                    "mode": "time",
                    "name": null,
                    "show": true,
                    "values": []
                    },
                    "yaxes": [
                    {
                        "format": "short",
                        "label": "Average Latency (ms)",
                        "logBase": 1,
                        "max": null,
                        "min": null,
                        "show": true
                    },
                    {
                        "format": "short",
                        "label": null,
                        "logBase": 1,
                        "max": null,
                        "min": null,
                        "show": true
                    }
                    ],
                    "yaxis": {
                    "align": false,
                    "alignLevel": null
                    }
                },
                {
                    "aliasColors": {},
                    "bars": false,
                    "dashLength": 10,
                    "dashes": false,
                    "datasource": "Approute",
                    "decimals": 2,
                    "fieldConfig": {
                    "defaults": {
                        "custom": {}
                    },
                    "overrides": []
                    },
                    "fill": 1,
                    "fillGradient": 0,
                    "gridPos": {
                    "h": 9,
                    "w": 12,
                    "x": 12,
                    "y": 0
                    },
                    "hiddenSeries": false,
                    "id": 4,
                    "legend": {
                    "avg": false,
                    "current": false,
                    "max": false,
                    "min": false,
                    "show": true,
                    "total": false,
                    "values": false
                    },
                    "lines": true,
                    "linewidth": 1,
                    "nullPointMode": "null",
                    "options": {
                    "dataLinks": []
                    },
                    "percentage": false,
                    "pointradius": 2,
                    "points": false,
                    "renderer": "flot",
                    "seriesOverrides": [],
                    "spaceLength": 10,
                    "stack": false,
                    "steppedLine": false,
                    "targets": [
                    {
                        "groupBy": [
                        {
                            "params": [
                            "$__interval"
                            ],
                            "type": "time"
                        },
                        {
                            "params": [
                            "Tunnel"
                            ],
                            "type": "tag"
                        }
                        ],
                        "measurement": "approute_stats",
                        "orderByTime": "ASC",
                        "policy": "default",
                        "refId": "A",
                        "resultFormat": "time_series",
                        "select": [
                        [
                            {
                            "params": [
                                "loss"
                            ],
                            "type": "field"
                            },
                            {
                            "params": [],
                            "type": "distinct"
                            }
                        ]
                        ],
                        "tags": []
                    }
                    ],
                    "thresholds": [],
                    "timeFrom": null,
                    "timeRegions": [],
                    "timeShift": null,
                    "title": "Loss",
                    "tooltip": {
                    "shared": true,
                    "sort": 0,
                    "value_type": "individual"
                    },
                    "type": "graph",
                    "xaxis": {
                    "buckets": null,
                    "mode": "time",
                    "name": null,
                    "show": true,
                    "values": []
                    },
                    "yaxes": [
                    {
                        "format": "short",
                        "label": "Average Loss (%)",
                        "logBase": 1,
                        "max": null,
                        "min": null,
                        "show": true
                    },
                    {
                        "format": "short",
                        "label": null,
                        "logBase": 1,
                        "max": null,
                        "min": null,
                        "show": true
                    }
                    ],
                    "yaxis": {
                    "align": false,
                    "alignLevel": null
                    }
                },
                {
                    "aliasColors": {},
                    "bars": false,
                    "dashLength": 10,
                    "dashes": false,
                    "datasource": "Approute",
                    "decimals": 0,
                    "fieldConfig": {
                    "defaults": {
                        "custom": {}
                    },
                    "overrides": []
                    },
                    "fill": 1,
                    "fillGradient": 0,
                    "gridPos": {
                    "h": 10,
                    "w": 24,
                    "x": 0,
                    "y": 9
                    },
                    "hiddenSeries": false,
                    "id": 6,
                    "legend": {
                    "avg": false,
                    "current": false,
                    "max": false,
                    "min": false,
                    "show": true,
                    "total": false,
                    "values": false
                    },
                    "lines": true,
                    "linewidth": 1,
                    "nullPointMode": "null",
                    "options": {
                    "dataLinks": []
                    },
                    "percentage": false,
                    "pointradius": 2,
                    "points": false,
                    "renderer": "flot",
                    "seriesOverrides": [],
                    "spaceLength": 10,
                    "stack": false,
                    "steppedLine": false,
                    "targets": [
                    {
                        "groupBy": [
                        {
                            "params": [
                            "$__interval"
                            ],
                            "type": "time"
                        },
                        {
                            "params": [
                            "Tunnel"
                            ],
                            "type": "tag"
                        }
                        ],
                        "measurement": "approute_stats",
                        "orderByTime": "ASC",
                        "policy": "default",
                        "refId": "A",
                        "resultFormat": "time_series",
                        "select": [
                        [
                            {
                            "params": [
                                "jitter"
                            ],
                            "type": "field"
                            },
                            {
                            "params": [],
                            "type": "distinct"
                            }
                        ]
                        ],
                        "tags": []
                    }
                    ],
                    "thresholds": [],
                    "timeFrom": null,
                    "timeRegions": [],
                    "timeShift": null,
                    "title": "Jitter",
                    "tooltip": {
                    "shared": true,
                    "sort": 0,
                    "value_type": "individual"
                    },
                    "type": "graph",
                    "xaxis": {
                    "buckets": null,
                    "mode": "time",
                    "name": null,
                    "show": true,
                    "values": []
                    },
                    "yaxes": [
                    {
                        "format": "short",
                        "label": "Average Jitter (ms)",
                        "logBase": 1,
                        "max": null,
                        "min": null,
                        "show": true
                    },
                    {
                        "format": "short",
                        "label": "",
                        "logBase": 1,
                        "max": null,
                        "min": null,
                        "show": true
                    }
                    ],
                    "yaxis": {
                    "align": false,
                    "alignLevel": null
                    }
                }
                ],
                "schemaVersion": 25,
                "style": "dark",
                "tags": [],
                "templating": {
                "list": []
                },
                "time": {
                "from": "now-24h",
                "to": "now"
                },
                "timepicker": {
                "refresh_intervals": [
                    "10s",
                    "30s",
                    "1m",
                    "5m",
                    "15m",
                    "30m",
                    "1h",
                    "2h",
                    "1d"
                ]
                },
                "timezone": "",
                "title": "Application Aware Routing Statistics",
                "version": 12
            },
            "overwrite": true,
            "inputs": [],
            "folderId": 0
            }

headers = {
            'Content-Type': "application/json",
            'Authorization': "Bearer " + api_key,
          }

response = requests.request("POST", url, data=json.dumps(payload), headers=headers)

if response.status_code == 200:
    print("Added Application Aware Routing Statistics dashboards")
else:
    print(response.text)
    print("Failed to add dashboards")
    exit()