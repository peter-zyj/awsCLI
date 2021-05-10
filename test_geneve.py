import os, sys
import re, hashlib, time
import atexit

import pytest

from awsAPIv3 import aws
from lib_yijun import *


def load_asa_config(asa_address, debug=False):
    import pexpect

    # asa_address = "ssh -i 'testDog.pem' admin@3.142.241.180"

    conn = pexpect.spawn(asa_address)
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("en")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("copy http://20.0.250.10/geneve.smp disk0:/.")
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

    return conn, result, cont


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


@pytest.mark.tcp
def test_tcp_reset():
    pass


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


@pytest.mark.udp
def test_udp_geneve():
    pass


@pytest.mark.cli
def test_show():
    cmd = "show asp drop frame geneve-invalid-nve-peer"
    # cmd = "show run"
    asa_address = "ssh -i 'testDog.pem' admin@18.144.54.235"
    _, _, res = asa_config(asa_address, cmd)

    assert "Last clearing: Never" in res


@pytest.mark.updowngrade
def test_image_replacement(keyFile):
    print("keyFile::", keyFile)
    return
    obj = aws(setting, record=False)
    res = obj.blind("Test-1-169-EC2-ASA", "EC2INSTANCE")
    res2 = res = obj.blind("Test-1-169-EC2-ASA-JB", "EC2INSTANCE")
    # backup config in ASA
    cmd = "show run"
    asa_address = f"ssh -i 'testDog.pem' admin@{res['public_ip']}"
    old_config = asa_config(asa_address, cmd)
    assert old_config != ""
    # transfer image to asa
    new_image = "geneve_new.smp"
    command = f"scp -i {keyFile} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             f"{new_image} ubuntu@{res2['public_ip']}:/var/www/html/."
    os.popen(command).read()

    import pexpect
    conn = pexpect.spawn(asa_address)
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("en")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("copy http://20.0.250.10/geneve_new.smp disk0:/.")
    conn, result, cont = Geneve_reply(conn, timeout=120, debug=debug)

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
