import os, sys
import re, hashlib, time
import atexit
from scapy.all import *

import pytest

from awsAPIv3 import aws
from lib_yijun import *


def load_asa_config(asa_address, asa_jb_ip="20.0.250.10", debug=False):
    import pexpect

    # asa_address = "ssh -i 'testDog.pem' admin@3.142.241.180"

    conn = pexpect.spawn(asa_address)
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("en")
    conn, result, cont = Geneve_reply(conn)

    # conn.sendline("copy http://20.0.250.10/geneve.smp disk0:/.")
    conn.sendline(f"copy http://{asa_jb_ip}/geneve.smp disk0:/.")
    conn, result, cont = Geneve_reply(conn, timeout=120, debug=debug)

    conn.sendline("conf term")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("boot system disk0:/geneve.smp")
    conn, result, cont = Geneve_reply(conn)

    # if debug:
    #     print("~~~~~~Debug~~~~~~~")
    #     print('WAITED', wait(600))
    #     pytest.skip("Time to debug ASA error before reload")

    conn.sendline("reload")
    conn, result, cont = Geneve_reply(conn, debug=debug)

    print('WAITED', wait(600))
    conn.close();
    del conn

    conn = pexpect.spawn(asa_address)
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("en")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("conf term")
    conn, result, cont = Geneve_reply(conn)

    # asa load pytest_day999.txt
    Geneve_load(conn, "pytest_day999.txt")

    conn.sendline("show run")
    conn, result, cont = Geneve_reply(conn)
    assert "20.0.1.101" in cont


def asa_config(asa_address, lines, debug=False) -> tuple:
    import pexpect

    conn = pexpect.spawn(asa_address)
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("en")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("conf term")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline(lines)
    conn, result, cont = Geneve_reply(conn, debug=debug)

    conn.close()
    del conn
    return result, cont


@pytest.fixture(scope="module", autouse=True)
def setup(request):
    skip_updown = request.config.option.skip_updown
    if skip_updown:
        print("\nsetup/teardown: skipped")
        return

    global setting, aws_obj
    setting = {}

    with open("/Users/yijunzhu/.aws/config_auto", "r") as f:
        cfg = f.read()
    with open("/Users/yijunzhu/.aws/credentials_auto", "r") as f:
        cda = f.read()

    setting["config"] = cfg
    setting["credentials"] = cda

    with open("/Users/yijunzhu/.aws/config", "r") as f:
        bytes_str = f.read().encode()
        md5_default_config = hashlib.md5(bytes_str).digest()
    with open("/Users/yijunzhu/.aws/credentials", "r") as f:
        bytes_str = f.read().encode()
        md5_default_credentials = hashlib.md5(bytes_str).digest()

    debug = request.config.option.trs
    aws_obj = aws(setting, debug=debug)
    atexit.register(aws_obj.close)

    aws_obj.load_deployment(fileName="aws_tb_pytest_west_1.config")
    aws_obj.start_deployment()

    asa_ip = aws_obj.fetch_address("Test-1-169-EC2-ASA")
    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"

    load_asa_config(asa_address, debug)

    def teardown():
        aws_obj.close()

        with open("/Users/yijunzhu/.aws/config", "r") as f:
            bytes_str = f.read().encode()
            md5_default_config_v = hashlib.md5(bytes_str).digest()
        with open("/Users/yijunzhu/.aws/credentials", "r") as f:
            bytes_str = f.read().encode()
            md5_default_credentials_v = hashlib.md5(bytes_str).digest()

        assert md5_default_config == md5_default_config_v
        assert md5_default_credentials == md5_default_credentials_v

    request.addfinalizer(teardown)


@pytest.mark.basic1to2
def test_Basic_PingGoogle():
    print("@@@@@@@@@start test:test_Basic_PingGoogle@@@@@@@@@")
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    jb_ip = aws_obj.fetch_address("Test-1-169-EC2-App-JB")

    ssh.connect(jb_ip, username='ubuntu', password='', key_filename="testDog.pem")

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'testDog.pem' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'ping 8.8.8.8 -c 1'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    assert "0% packet loss" in resp1
    ssh.close()


@pytest.mark.basic2to1
def test_Basic_PingApp():
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    jb_ip = aws_obj.fetch_address("Test-EC2-App-JB")
    elip = aws_obj.fetch_address("Test-EC2-App")

    access_list = "access-list geneve extended permit icmp host {jb_ip} host 10.0.1.101"

    asa_ip = aws_obj.fetch_address("Test-EC2-ASA")
    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"

    asa_config(asa_address, access_list)

    ssh.connect(jb_ip, username='ubuntu', password='', key_filename="testDog.pem")

    while True:
        _, stdout, _ = ssh.exec_command(f"ping {elip} -c 1")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    assert "0% packet loss" in resp1
    ssh.close()


@pytest.mark.install
def test_apt_install():
    print("Start test_apt_install")
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    jb_ip = aws_obj.fetch_address("Test-EC2-App-JB")

    ssh.connect(jb_ip, username='ubuntu', password='', key_filename="testDog.pem")

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'testDog.pem' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'sudo apt install net-tools'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    while True:
        _, stdout2, _ = ssh.exec_command("ssh -i 'testDog.pem' -o StrictHostKeyChecking=no "
                                         "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'ifconfig'")
        stdout2.channel.recv_exit_status()
        resp2 = "".join(stdout2.readlines())
        if not resp2:
            continue
        else:
            break

    assert "10.0.1.101" in resp2

    ssh.close()

@pytest.mark.pyserver
def test_PYSERVER(skip_updown):
    print("skip_updown:", skip_updown)
    # asa_jb_address = "ssh -i 'testDog.pem' ubuntu@54.219.169.240"
    # asa_address = "ssh -i 'testDog.pem' ubuntu@54.241.122.28"

    # 1. transfer server file
    cmd1 = "scp -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@13.57.178.96:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@13.57.178.96 'scp -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@13.52.150.43:/home/ubuntu/.'"
    os.popen(cmd2).read()

    cmd3 = "scp -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@13.57.48.179:/home/ubuntu/."
    os.popen(cmd3).read()

    # 2. run server file
    # cmd3 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
    #        "ubuntu@54.219.169.240 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
    #        "ubuntu@54.241.122.28 \'sudo screen -d -m sudo python3 Pytest_server.py\''"
    # os.popen(cmd3).read()


@pytest.mark.tcp
@pytest.mark.tcp23
def test_TCP23(skip_updown):
    print("skip_updown:", skip_updown)
    # asa_jb_address = "ssh -i 'testDog.pem' ubuntu@3.101.116.24"
    # asa_address = "ssh -i 'testDog.pem' ubuntu@54.241.122.28"

    # 1. transfer server file
    cmd1 = "scp -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@3.101.116.24:/home/ubuntu/."
    os.popen(cmd1).read()
    cmd2 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@3.101.116.24 'scp -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@54.241.122.28:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd3 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@3.101.116.24 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@54.241.122.28 \'sudo screen -d -m sudo python3 Pytest_server.py\''"

    os.popen(cmd3).read()

    # 3. test
    test = """
import socket
s=socket.socket()
s.connect(("54.241.122.28",23))
s.send("Yijun is coming".encode())
msg = s.recv(1024)
print(msg)
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "test.py ubuntu@3.101.116.24:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd5 = "ssh -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@3.101.116.24 'sudo python3 test.py'"
    resp = os.popen(cmd5).read()

    assert "[Pytest]TCP:23 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@3.101.116.24 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd7 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@3.101.116.24 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@54.241.122.28 \'sudo pkill python3\''"

    os.popen(cmd7).read()


@pytest.mark.udp
@pytest.mark.udp666
def test_UDP666(skip_updown):
    print("skip_updown:", skip_updown)
    # 1. transfer server file
    cmd1 = "scp -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@3.101.116.24:/home/ubuntu/."
    os.popen(cmd1).read()
    cmd2 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@3.101.116.24 'scp -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@54.241.122.28:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd3 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@3.101.116.24 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@54.241.122.28 \'sudo screen -d -m sudo python3 Pytest_server.py\''"

    os.popen(cmd3).read()

    # 3. test
    test = """
import socket
s=socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
s.sendto("Yijun is coming".encode(), ("54.241.122.28", 666))
msg = s.recvfrom(1024)
print(msg[0])
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "test.py ubuntu@3.101.116.24:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd5 = "ssh -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@3.101.116.24 'sudo python3 test.py'"
    resp = os.popen(cmd5).read()

    assert "[Pytest]UDP:666 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@3.101.116.24 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd7 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@3.101.116.24 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@54.241.122.28 \'sudo pkill python3\''"

    os.popen(cmd7).read()


@pytest.mark.counter
def test_udp_counter():

    cmd1 = "clear asp drop"
    cmd2 = "show asp drop frame geneve-invalid-udp-checksum"

    asa_address = "ssh -i 'testDog.pem' admin@54.183.212.66"
    _, _ = asa_config(asa_address, cmd1)

    send(IP(dst="20.0.1.101") / UDP(sport=20001, dport=6081, chksum=0)/b'\x08\x00\x08')

    _, res = asa_config(asa_address, cmd2)
    assert "geneve-invalid-udp-checksum" in res


@pytest.mark.reset
def test_tcp_counter():
    cmd = "show asp drop frame geneve-invalid-udp-checksum"
    # cmd = "show run"
    asa_address = "ssh -i 'testDog.pem' admin@18.144.54.235"
    _, res = asa_config(asa_address, cmd)

    assert "Last clearing: Never" in res


@pytest.mark.genevedebug
def test_debug_geneve():
    cmd1 = "debug geneve encapsulation"
    cmd2 = "debug geneve encapsulation 4"
    cmd3 = "debug geneve decapsulation"
    cmd4 = "debug geneve decapsulation 4"
    cmd5 = "debug geneve all"
    cmd_clean = "unde all"
    cmd_show = "show debug"

    asa_address = "ssh -i 'testDog.pem' admin@54.183.212.66"

    import pexpect

    conn = pexpect.spawn(asa_address)
    _, _, _ = Geneve_reply(conn)

    conn.sendline("en")
    _, _, _ = Geneve_reply(conn)

    conn.sendline(cmd_clean)
    _, _, _ = Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve" not in res

    conn.sendline(cmd_clean)
    _, _, _ = Geneve_reply(conn)
    conn.sendline(cmd1)
    _, _, _ = Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve encapsulation enabled at level 1" in res

    conn.sendline(cmd_clean)
    _, _, _ = Geneve_reply(conn)
    conn.sendline(cmd2)
    _, _, _ = Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve encapsulation enabled at level 4" in res

    conn.sendline(cmd_clean)
    _, _, _ = Geneve_reply(conn)
    conn.sendline(cmd3)
    _, _, _ = Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve decapsulation enabled at level 1" in res

    conn.sendline(cmd_clean)
    _, _, _ = Geneve_reply(conn)
    conn.sendline(cmd4)
    _, _, _ = Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve decapsulation enabled at level 4" in res

    conn.sendline(cmd_clean)
    _, _, _ = Geneve_reply(conn)
    conn.sendline(cmd5)
    _, _, _ = Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve encapsulation enabled at level 1" in res
    assert "debug geneve decapsulation enabled at level 1" in res

    conn.sendline(cmd_clean)
    _, _, _ = Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve" not in res

    conn.close()
    del conn

@pytest.mark.addasa
def test_addASA():
    cont ='''
pytest_ASA_New(EC2INSTANCE):
  image-id: ami-01cab33393210e391
  instance-type: c5.xlarge
  key-name: testDog
  security-group-ids: Test-1-169_SG_Sec_MGMT
  count: 1
  subnet-id: Test-1-169_SUB_Sec_MGMT
  associate-public-ip-address: None
  private-ip-address: 20.0.250.12
  user-data: file://pytest_day0.txt
  action:
    query_from:
        - Test-1-169_SUB_Sec_MGMT
        - Test-1-169_SG_Sec_MGMT
    cleanUP: True

pytest_NWInterface_ASA_New(NETWORK_INTERFACE):
  subnet-id: Test-1-169_SUB_Sec_DATA
  description: Test-1-169 Data Network for ASA
  groups: Test-1-169_SG_Sec_DATA
  private-ip-address: 20.0.1.102
  action:
    query_from:
      - Test-1-169_SG_Sec_DATA
      - Test-1-169_SUB_Sec_DATA
    cleanUP: True

pytest_NWInterface_ASA_Bind(BIND):
  network-interface-id: pytest_NWInterface_ASA_New
  instance-id: pytest_ASA_New
  device-index: 1
  action:
    bind_to:
      - pytest_NWInterface_ASA_New
      - pytest_ASA_New
    cleanUP: True

'''
    setting = {}
    cfg = {"default": {"region": "us-west-1", "output": "yaml"}}
    cda = {"default": {"aws_access_key_id": "AKIAWMUP3NI4ET7YU6AN", "aws_secret_access_key": "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"}}
    setting["config"] = cfg
    setting["credentials"] = cda

    obj = aws(setting, record=False)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    # asa_ip = obj.fetch_address("Auto_ASA_New")
    # asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"
    #
    # load_asa_config(asa_address, debug=False)

@pytest.mark.updowngrade
def test_image_replacement(keyFile, trs):
    print("keyFile::", keyFile)
    print("Debug::", trs)

    obj = aws(record=False)
    res1 = obj.blind("Test-1-169-EC2-ASA", "EC2INSTANCE")
    res2 = res = obj.blind("Test-1-169-EC2-ASA-JB", "EC2INSTANCE")
    # backup config in ASA
    cmd = "show run"
    asa_address = f"ssh -i 'testDog.pem' admin@{res1['public_ip']}"
    old_config = asa_config(asa_address, cmd)
    assert old_config != ""
    # transfer image to asa
    new_image = "geneve_new.smp"
    command = f"scp -i {keyFile} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             f"{new_image} ubuntu@{res2['public_ip']}:/var/www/html/."

    timer("start")
    os.popen(command).read()
    timer("stop")

    import pexpect
    debug = trs
    conn = pexpect.spawn(asa_address)
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("en")
    conn, result, cont = Geneve_reply(conn)

    print("debug:start copy")
    conn.sendline("copy http://20.0.250.10/geneve_new.smp disk0:/geneve_new.smp")
    conn, result, cont = Geneve_reply(conn, timeout=120, debug=debug)
    print("debug:end copy")

    # print old version
    conn.sendline("show version")
    conn, result, cont = Geneve_reply(conn, timeout=120, debug=debug)

    print("Old Version::",cont)

    # reload asa
    conn.sendline("boot system disk0:/geneve_new.smp")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("reload")
    conn, result, cont = Geneve_reply(conn, debug=debug)

    print('WAITED', wait(600))
    conn.close();
    del conn


    # print new version
    conn = pexpect.spawn(asa_address)
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("en")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("show version")
    conn, result, cont = Geneve_reply(conn, timeout=120, debug=debug)

    print("New Version::",cont)

    # config is same as before/after
    cmd = "show run"
    asa_address = f"ssh -i 'testDog.pem' admin@{res['public_ip']}"
    new_config = asa_config(asa_address, cmd)

    temp = new_config.replace("geneve_new.smp", "geneve.smp")
    assert temp == old_config

    pass



if __name__ == '__main__':
    pytest.main(["-q", "-s", "-ra", "test_geneve.py"])
# capture abc interface data-interface
# show capture abc packet-number 18 detail decode
#
# copy /pcap capture:abc abc.pcap
#
# copy disk0:/abc.pcap scp://root@1.2.3.4:/home/ubuntu/.

#######################
# access-list geneve extended permit icmp host 3.101.116.24 host 10.0.1.101
# access-list geneve extended permit tcp host 3.101.116.24 host 10.0.1.101
# access-list geneve extended permit udp host 3.101.116.24 host 10.0.1.101
#######################
# direct vs roundway

# aaa authentication listener http data-interface port www
# ~~~~exclusive~~~~
# object network gwlb-net
# subnet 20.0.1.0 255.255.255.0
#
# object-group network gwlb
# network-object object gwlb-net
#
# object-group network metadata
# network-object host 20.0.1.10
#
# object service http80
# service tcp destination eq www
#
# nat (data-interface,data-interface) source static gwlb interface destination static interface metadata service http80 http80
#
