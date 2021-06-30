import re, os, sys
import time, datetime, random
import requests
import yaml, json

with open("config.yaml", "r") as f:
    cont = f.read()

cfg = yaml.load(cont, Loader=yaml.FullLoader)
headers = {}
headers["Authorization"] = f"Token {cfg['token']}"
headers["Content-Type"] = "text/plain"
headers["Accept"] = "application/x-yaml"

def show():
    pass

def upload(record_list):
    raw_url = "http://" + cfg['address'] + "@uri@" + \
          f"?org={cfg['org']}&bucket={cfg['bucket']}&precision={cfg['precision']}"

    data = ""
    for record in record_list:
        url = raw_url.replace("@uri@", "/api/v2/write")
        data += record + "\n"

    resp = requests.post(url, headers=headers, verify=False, data=data)
    return str(resp)




# influx query 'from(bucket:"pytest") |> range(start:-2000m)' --raw
# influx delete --bucket pytest -p '_measurement=test_cases AND host="wocao"' --start 1970-01-01T00:00:00Z --stop $(date +"%Y-%m-%dT%H:%M:%SZ") -o cisco

if __name__ == '__main__':
    raw_url = "http://" + cfg['address'] + "@uri@" + \
          f"?org={cfg['org']}&bucket={cfg['bucket']}&precision={cfg['precision']}"
    # print(headers)

    # Write
    url = raw_url.replace("@uri@", "/api/v2/write")
    print (url)
    data = 'testcases_Jun_21,name=geneve_ping version="7.1"'
    r1 = requests.post(url, headers=headers, verify=False, data=data)

    # Write
    url = raw_url.replace("@uri@", "/api/v2/write")
    print (url)
    num = random.randint(1, 100)
    result = ["Pass","Fail","No_Result"]
    res = result[num % 3]
    data = ""
    data += f'testcases_Jun_23,name=geneve_rule,result={res},version=7.1,method=auto index={num}'
    # data += f'testcases_Jun_21,name=geneve_ping result="{res}"' + '\n'
    # data += f'testcases_Jun_21,name=geneve_ping index={num}' + '\n'
    # data += 'testcases_Jun_21,name=geneve_ping method="auto"'
    r1 = requests.post(url, headers=headers, verify=False, data=data)
    print(r1)


    # Query
    url = raw_url.replace("@uri@", "/api/v2/query")
    print (url)
    raw_data = {}
    raw_data['query'] = 'from(bucket: \"pytest\") |> range(start: -1h)'
    data = json.dumps(raw_data)
    resp = requests.post(url, headers=headers, verify=False, data=data)
    resp_body = resp.content.decode("utf-8")
    print(resp_body)

    print('~~~~~~~~~~~term~~~~~~~~~~~')
    #delete
    url = raw_url.replace("@uri@", "/api/v2/delete")
    print(url)
    raw_data = {}
    raw_data['predicate'] = '_measurement=testcases_Jun_23 and name="geneve_rule"'
    raw_data['start'] = '1970-01-01T00:00:00Z'
    raw_data['stop'] = (datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(raw_data)
    data = json.dumps(raw_data)
    r1 = requests.post(url, headers=headers, verify=False, data=data)
    print(r1)


    # Query
    url = raw_url.replace("@uri@", "/api/v2/query")
    print (url)
    raw_data = {}
    raw_data['query'] = 'from(bucket: \"pytest\") |> range(start: -1h)'
    data = json.dumps(raw_data)
    resp = requests.post(url, headers=headers, verify=False, data=data)
    resp_body = resp.content.decode("utf-8")
    print(resp_body)