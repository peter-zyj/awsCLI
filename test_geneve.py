import os, sys
import re, hashlib,time
import atexit

import pytest

from awsAPIv2 import aws
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
    conn.close(); del conn

    conn = pexpect.spawn(asa_address)
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("en")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("conf term")
    conn, result, cont = Geneve_reply(conn)

    #asa load pytest_day999.txt
    Geneve_load(conn, "pytest_day999.txt")

    conn.sendline("show run")
    conn, result, cont = Geneve_reply(conn)
    assert "20.0.1.101" in cont

def asa_config(asa_address, lines, debug=False):
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
    aws_obj = aws(setting,debug=debug)
    atexit.register(aws_obj.close)

    aws_obj.load_deployment(fileName="aws_tb_pytest_west_1.config")
    aws_obj.start_deployment()

    asa_ip = aws_obj.fetch_address("Test-EC2-ASA")
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
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    jb_ip = aws_obj.fetch_address("Test-EC2-App-JB")

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

@pytest.mark.tcp
@pytest.mark.tcp23
def test_ssh(skip_updown):
    print("skip_updown:",skip_updown)
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

    #3. test
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
def test_nslookup():
    pass

@pytest.mark.udp
def test_udp_packet():
    pass

@pytest.mark.udp
def test_udp_geneve():
    pass