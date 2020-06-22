# SD-WAN APIs Integration With Devops Tools Code

# Objective 

*   How to use vManage APIs to retrieve Enterprise Firewall Aggregation Statistics.

# Requirements

To use this code you will need:

* Python 3.7+
* vManage user login details.

# Install and Setup

- Clone the code to local machine.

```
git clone https://github.com/CiscoDevNet/sd-wan_integration_with_devops_tools_code.git
cd sd-wan_integration_with_devops_tools_code
```
- Setup Python Virtual Environment (requires Python 3.7+)

```
python3.7 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

- Create **vmanage_login.yaml** using below sample format to provide the login details of vManage

## Example:

```
# vManage Connectivity Info
vmanage_host:
vmanage_port:
vmanage_username:
vmanage_password:
```