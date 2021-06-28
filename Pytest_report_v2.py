from bs4 import BeautifulSoup
import os,sys,re
import collections, datetime
import influxdb_yijun


# tp_name = sys.argv[1]
# cmd: pytest -v -s -m basic1to2 --skip_updown --html=report.html --self-contained-html --metadata Version 7.1

cont  = open("report.html","r").read()
soup = BeautifulSoup(cont, 'html.parser')

result_list = soup.find_all("td", {"class": "col-result"})
case_list = soup.find_all("td", {"class": "col-name"})
dur_list = soup.find_all("td", {"class": "col-duration"})

try:
    ver_patten = "(?s)<td>Version</td>.*?<td>(.*?)</td>"
    test_version = re.compile(ver_patten).findall(cont)[0]
except:
    test_version = "Unknown"

try:
    time_raw = soup.find_all(string=re.compile("Report generated on"))[0].strip()
    test_Tstamp = time_raw.split()[3] + "_" + time_raw.split()[5].replace(":", "_")
except:
    test_Tstamp = (datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")

if len(result_list) != len(case_list):
    print("[ERROR] number mismatch between case result and case name")
    sys.exit(1)

simple_result = collections.defaultdict(dict)
for idx in range(len(result_list)):
    key = case_list[idx].text
    value = result_list[idx].text
    duration = dur_list[idx].text
    simple_result[key]["Result"] = value
    simple_result[key]["Duration"] = duration

if not simple_result:
    print("[ERR]no result found in test report")
    sys.exit(1)

# print(simple_result)
record_list = []
for key,val in simple_result.items():
    test_table, test_name = key.split("::")
    #TBD test_table posfix time(from report)
    #TBD test_version (from report)  plugin:pytest-metadata
    test_duration = val["Duration"]
    test_result = val["Result"]
    record = f"{test_table}_{test_Tstamp},name={test_name},result={test_result},version={test_version} duration={test_duration}"

    record_list.append(record)

# for i in record_list:
#     print(i)
result = influxdb_yijun.upload(record_list)
print(result)
