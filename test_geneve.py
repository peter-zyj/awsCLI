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

    conn = None
    while not conn:
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

    Basic_miss_config()

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


def Basic_miss_config():
    print("####Basic_miss_config test####")
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

    assert "100% packet loss" in resp1
    ssh.close()


@pytest.mark.basic1to2
def test_Basic_PingGoogle(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="testDog.pem")

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
def test_Basic_PingApp(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"

    access_list = f"access-list geneve extended permit icmp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, access_list)

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="testDog.pem")

    while True:
        _, stdout, _ = ssh.exec_command(f"ping {app_ip} -c 1")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    assert "0% packet loss" in resp1

    no_access_list = f"no access-list geneve extended permit icmp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_access_list)
    ssh.close()


@pytest.mark.install1to2
def test_apt_install_from_outside(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="testDog.pem")

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


@pytest.mark.install2to1
def test_apt_install_from_inside(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"

    access_list = f"access-list geneve extended permit tcp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, access_list)

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="testDog.pem")

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'testDog.pem' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'sudo apt install apache2 -y'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    while True:
        _, stdout2, _ = ssh.exec_command(f"wget http://{app_ip}/index.html; ls index.html")

        stdout2.channel.recv_exit_status()
        resp2 = "".join(stdout2.readlines())
        if not resp2:
            continue
        else:
            break

    assert "No such file or directory" not in resp2

    no_access_list = f"no access-list geneve extended permit tcp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_access_list)
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
@pytest.mark.tcp1to2
def test_TCP23_from_outside(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run

    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"
    acl_config = f"access-list geneve extended permit tcp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, acl_config)

    # 1. transfer server file
    cmd1 = "scp -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"Pytest_server.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'scp -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd_k = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
            f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
            "ubuntu@10.0.1.101 \'sudo pkill python3\''"

    os.popen(cmd_k).read()

    cmd3 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo screen -d -m sudo python3 Pytest_server.py\''"

    os.popen(cmd3).read()

    # 3. test
    test = f"""
import socket
s=socket.socket()
s.connect(("{app_ip}",23))
s.send("Yijun is coming".encode())
msg = s.recv(1024)
print(msg)
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"test.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd5 = "ssh -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3;python3 test.py'"
    resp = os.popen(cmd5).read()

    assert "[Pytest]TCP:23 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd7 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo pkill python3\''"

    os.popen(cmd7).read()

    no_acl_config = f"no access-list geneve extended permit tcp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_acl_config)


@pytest.mark.tcp
@pytest.mark.tcp2to1
def test_TCP23_from_inside(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run

    # 1. transfer server file
    cmd1 = "scp -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"Pytest_server.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'scp -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd3 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3;sudo screen -d -m sudo python3 Pytest_server.py'"

    os.popen(cmd3).read()

    # 3. test
    test = f"""
import socket
s=socket.socket()
s.connect(("{app_jb_ip}",23))
s.send("Yijun is coming".encode())
msg = s.recv(1024)
print(msg)
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"test.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd4_2 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             f"ubuntu@{app_jb_ip} 'scp -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             "test.py ubuntu@10.0.1.101:/home/ubuntu/.'"

    os.popen(cmd4_2).read()

    cmd5 = "ssh -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo pkill python3;python3 test.py\''"
    resp = os.popen(cmd5).read()

    assert "[Pytest]TCP:23 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd6_2 = "ssh -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             "ubuntu@10.0.1.101 \'sudo rm -rf test.py\''"
    os.popen(cmd6_2).read()

    cmd7 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3'"

    os.popen(cmd7).read()


@pytest.fixture()
def local_run():
    if "aws_obj" in globals():
        app_jb = aws_obj.blind("Test-1-169-EC2-App-JB", "EC2INSTANCE")
        asa_jb = aws_obj.blind("Test-1-169-EC2-ASA-JB", "EC2INSTANCE")
        asa = aws_obj.blind("Test-1-169-EC2-ASA", "EC2INSTANCE")
        app = aws_obj.blind("Test-1-169-EC2-App", "EC2INSTANCE")

    else:
        aws_obj = aws(record=False)
        app_jb = aws_obj.blind("Test-1-169-EC2-App-JB", "EC2INSTANCE")
        asa_jb = aws_obj.blind("Test-1-169-EC2-ASA-JB", "EC2INSTANCE")
        asa = aws_obj.blind("Test-1-169-EC2-ASA", "EC2INSTANCE")
        app = aws_obj.blind("Test-1-169-EC2-App", "EC2INSTANCE")

    app_jb_ip = app_jb["public_ip"]
    asa_jb_ip = asa_jb["public_ip"]
    asa_ip = asa["public_ip"]
    app_ip = app["public_ip"]

    yield app_jb_ip, asa_jb_ip, asa_ip, app_ip
    aws_obj.close()


@pytest.fixture()
def acl_config(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run

    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"
    acl_config = f"access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, acl_config)

    yield

    no_acl_config = f"no access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_acl_config)


@pytest.mark.udpYijun
# def test_UDP666(acl_config):
def test_UDP666(local_run, acl_config):
    # if "aws_obj" in globals():
    #     app_jb = aws_obj.blind("Test-1-169-EC2-App-JB", "EC2INSTANCE")
    #     asa_jb = aws_obj.blind("Test-1-169-EC2-ASA-JB", "EC2INSTANCE")
    #     asa = aws_obj.blind("Test-1-169-EC2-ASA", "EC2INSTANCE")
    #     app = aws_obj.blind("Test-1-169-EC2-App", "EC2INSTANCE")
    #
    # else:
    #     aws_obj = aws(record=False)
    #     app_jb = aws_obj.blind("Test-1-169-EC2-App-JB", "EC2INSTANCE")
    #     asa_jb = aws_obj.blind("Test-1-169-EC2-ASA-JB", "EC2INSTANCE")
    #     asa = aws_obj.blind("Test-1-169-EC2-ASA", "EC2INSTANCE")
    #     app = aws_obj.blind("Test-1-169-EC2-App", "EC2INSTANCE")
    #
    # app_jb_ip = app_jb["public_ip"]
    # asa_jb_ip = asa_jb["public_ip"]
    # asa_ip = asa["public_ip"]
    # app_ip = app["public_ip"]

    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run

    # asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"
    # acl_config = f"access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    # asa_config(asa_address, acl_config)

    # 1. transfer server file
    cmd1 = "scp -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"Pytest_server.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'scp -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd3 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo screen -d -m sudo python3 Pytest_server.py\''"

    os.popen(cmd3).read()

    # 3. test
    test = f"""
import socket
s=socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
s.sendto("Yijun is coming".encode(), ("{app_ip}", 666))
msg = s.recvfrom(1024)
print(msg[0])
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"test.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd5 = "ssh -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo python3 test.py'"
    resp = os.popen(cmd5).read()

    assert "[Pytest]UDP:666 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd7 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo pkill python3\''"

    os.popen(cmd7).read()

    # no_acl_config = f"no access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    # asa_config(asa_address, no_acl_config)


@pytest.mark.udp1to2
def test_UDP_from_inside(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run

    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"
    acl_config = f"access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, acl_config)

    # 1. transfer server file
    cmd1 = "scp -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"Pytest_server.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'scp -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd_k = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
            f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
            "ubuntu@10.0.1.101 \'sudo pkill python3\''"

    os.popen(cmd_k).read()
    cmd3 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo screen -d -m sudo python3 Pytest_server.py\''"

    os.popen(cmd3).read()

    # 3. test
    test = f"""
import socket
s=socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
s.sendto("Yijun is coming".encode(), ("{app_ip}", 666))
msg = s.recvfrom(1024)
print(msg[0])
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"test.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd5 = "ssh -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3;python3 test.py'"
    resp = os.popen(cmd5).read()

    assert "[Pytest]UDP:666 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd7 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo pkill python3\''"

    os.popen(cmd7).read()

    no_acl_config = f"no access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_acl_config)


@pytest.mark.udp2to1
def test_UDP_from_outside(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run

    # 1. transfer server file
    cmd1 = "scp -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"Pytest_server.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'scp -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd3 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3;sudo screen -d -m sudo python3 Pytest_server.py'"

    os.popen(cmd3).read()

    # 3. test
    test = f"""
import socket
s=socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
s.sendto("Yijun is coming".encode(), ("{app_jb_ip}", 666))
msg = s.recvfrom(1024)
print(msg[0])
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"test.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd4_2 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             f"ubuntu@{app_jb_ip} 'scp -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             "test.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd4_2).read()

    cmd5 = "ssh -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo pkill python3;python3 test.py\''"
    resp = os.popen(cmd5).read()
    assert "[Pytest]UDP:666 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd6_2 = "ssh -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             "ubuntu@10.0.1.101 \'sudo rm -rf test.py\''"
    os.popen(cmd6_2).read()

    cmd7 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3'"

    os.popen(cmd7).read()


@pytest.mark.iperfudp
def test_iperf_udp(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run

    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"
    acl_config = f"access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, acl_config)

    cmd1 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo screen -d -m sudo iperf -s -u'"

    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo iperf -c {app_jb_ip} -u\''"

    res = os.popen(cmd2).read()

    bd = re.compile(" ([\d.]+?) (?=MBytes)").findall(res)[0]
    assert float(bd) > 0

    cmd3 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill iperf'"

    os.popen(cmd3).read()

    no_acl_config = f"no access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_acl_config)


@pytest.mark.iperfudpreverse
def test_iperf_udp_reverse(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run

    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"
    acl_config = f"access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, acl_config)

    cmd1 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo screen -d -m sudo iperf -s -u\''"

    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo iperf -c {app_ip} -u;'"

    res = os.popen(cmd2).read()
    print("Iperf result:\n", res)

    bd = re.compile(" ([\d.]+?) (?=MBytes)").findall(res)[0]
    assert float(bd) > 0
    cmd3 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo pkill iperf\''"

    os.popen(cmd3).read()

    no_acl_config = f"no access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_acl_config)


@pytest.mark.iperftcp
def test_iperf_tcp(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run

    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"
    acl_config = f"access-list geneve extended permit tcp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, acl_config)

    cmd1 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo screen -d -m sudo iperf -s'"

    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo iperf -c {app_jb_ip}\''"

    res = os.popen(cmd2).read()

    bd = re.compile(" ([\d.]+?) (?=MBytes)").findall(res)[0]
    assert float(bd) > 0

    cmd3 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill iperf'"

    os.popen(cmd3).read()

    no_acl_config = f"no access-list geneve extended permit tcp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_acl_config)


@pytest.mark.iperftcpreverse
def test_iperf_tcp_reverse(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run

    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"
    acl_config = f"access-list geneve extended permit tcp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, acl_config)

    cmd1 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo screen -d -m sudo iperf -s\''"

    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo iperf -c {app_ip}'"

    res = os.popen(cmd2).read()

    print("Iperf result:\n", res)
    bd = re.compile(" ([\d.]+?) (?=MBytes)").findall(res)[0]
    assert float(bd) > 0

    cmd3 = "ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo pkill iperf\''"

    os.popen(cmd3).read()

    no_acl_config = f"no access-list geneve extended permit tcp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_acl_config)


@pytest.mark.counter
def test_udp_counter(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run
    cmd1 = "clear asp drop"
    cmd2 = "show asp drop frame geneve-invalid-udp-checksum"

    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"
    asa_config(asa_address, cmd1)

    send(IP(dst="20.0.1.101") / UDP(sport=20001, dport=6081, chksum=0) / b'\x08\x00\x08')

    _, res = asa_config(asa_address, cmd2)
    assert "geneve-invalid-udp-checksum" in res


@pytest.mark.reset
def test_tcp_counter(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run

    cmd = f"ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
          f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
          f"ubuntu@10.0.1.101 \'sudo screen -d -m ssh root@{asa_jb_ip}\''"

    os.popen(cmd).read()

    cmd2 = "clear conn address 10.0.1.101"
    cmd3 = "show asp drop"
    cmd1 = "clear asp drop"

    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"
    asa_config(asa_address, cmd1)
    asa_config(asa_address, cmd2)

    cmd = f"ssh  -i 'testDog.pem' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
          f"ubuntu@{app_jb_ip} 'ssh -i \'testDog.pem\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
          f"ubuntu@10.0.1.101 \'sudo pkill screen\''"

    os.popen(cmd).read()

    _, res = asa_config(asa_address, cmd3)

    assert "tcp-not-syn" in res


@pytest.mark.logserver
def test_log_server(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh2 = paramiko.SSHClient()
    ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="testDog.pem")
    ssh2.connect(asa_jb_ip, username='ubuntu', password='', key_filename="testDog.pem")

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'testDog.pem' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'ping 8.8.8.8 -c 10'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    assert "0% packet loss" in resp1

    _, stdout, _ = ssh2.exec_command("sudo systemctl restart syslog")
    stdout.channel.recv_exit_status()
    while True:
        _, stdout, _ = ssh2.exec_command("tail -n 100 /var/log/syslog")
        stdout.channel.recv_exit_status()
        resp2 = "".join(stdout.readlines())
        if not resp2:
            continue
        else:
            break

    assert "8.8.8.8" in resp2

    ssh.close()
    ssh2.close()


@pytest.mark.genevedebug
def test_debug_geneve(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run
    cmd1 = "debug geneve encapsulation"
    cmd2 = "debug geneve encapsulation 4"
    cmd3 = "debug geneve decapsulation"
    cmd4 = "debug geneve decapsulation 4"
    cmd5 = "debug geneve all"
    cmd_clean = "unde all"
    cmd_show = "show debug"

    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"

    import pexpect

    conn = pexpect.spawn(asa_address)
    Geneve_reply(conn)

    conn.sendline("en")
    Geneve_reply(conn)

    conn.sendline(cmd_clean)
    Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve" not in res

    conn.sendline(cmd_clean)
    Geneve_reply(conn)
    conn.sendline(cmd1)
    Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve encapsulation enabled at level 1" in res

    conn.sendline(cmd_clean)
    Geneve_reply(conn)
    conn.sendline(cmd2)
    Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve encapsulation enabled at level 4" in res

    conn.sendline(cmd_clean)
    Geneve_reply(conn)
    conn.sendline(cmd3)
    Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve decapsulation enabled at level 1" in res

    conn.sendline(cmd_clean)
    Geneve_reply(conn)
    conn.sendline(cmd4)
    Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve decapsulation enabled at level 4" in res

    conn.sendline(cmd_clean)
    Geneve_reply(conn)
    conn.sendline(cmd5)
    Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve encapsulation enabled at level 1" in res
    assert "debug geneve decapsulation enabled at level 1" in res

    conn.sendline(cmd_clean)
    Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve" not in res

    conn.close()
    del conn


@pytest.mark.metaserver
def test_meta(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run
    cmd1 = "no aaa authentication listener http data-interface port www"
    cmd2 = "nat (data-interface,data-interface) source static gwlb interface destination static interface metadata service http80 http80"

    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"
    asa_config(asa_address, cmd1)
    asa_config(asa_address, cmd2)
    time.sleep(20)
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="testDog.pem")

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


@pytest.mark.statistics
def test_stats(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run
    cmd1 = "show interface vni 1"
    cmd2 = "show nve 1"
    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"

    _, cont1_1 = asa_config(asa_address, cmd1)
    _, cont2_1 = asa_config(asa_address, cmd2)
    p1 = "(.*) packets input"
    p2 = "(.*) packets output"

    output_cmd1_1 = int(re.compile(p1).findall(cont1_1)[0])
    output_cmd2_1 = int(re.compile(p2).findall(cont2_1)[0])

    test_Basic_PingGoogle(local_run)

    _, cont1_2 = asa_config(asa_address, cmd1)
    _, cont2_2 = asa_config(asa_address, cmd2)

    output_cmd1_2 = int(re.compile(p1).findall(cont1_2)[0])
    output_cmd2_2 = int(re.compile(p2).findall(cont2_2)[0])

    assert output_cmd1_2 > output_cmd1_1
    assert output_cmd2_2 > output_cmd2_1

@pytest.mark.capture
def test_capture(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip = local_run
    cmd0 = "no cap g"
    cmd1 = "clear cap /all"
    cmd2 = "cap g int ge trace"
    cmd3 = "show capture g | in icmp: echo request"
    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"

    asa_config(asa_address, cmd0)
    asa_config(asa_address, cmd1)
    asa_config(asa_address, cmd2)
    test_Basic_PingGoogle(local_run)
    time.sleep(1)
    _, cont3 = asa_config(asa_address, cmd3)
    pNum = int(re.compile("\d+: ").findall(cont3)[0].strip().split(":")[0])
    cmd4 = f"show capture g trace packet-number {pNum}"
    cmd5 = "no cap g"
    _, cont4 = asa_config(asa_address, cmd4)
    assert "Action: allow" in cont4
    asa_config(asa_address, cmd5)



@pytest.mark.replace
@pytest.mark.reFTD
def test_replace_FTD():
    cont = '''
Del_Pytest_NWInterface_FTD1(TERMINATION):
  type: NETWORK_INTERFACE
  action:
    bind_to:
        - Del_Pytest-EC2-FTD
Del_Pytest_NWInterface_FTD2(TERMINATION):
  type: NETWORK_INTERFACE
  action:
    bind_to:
        - Del_Pytest-EC2-FTD
Del_Pytest_NWInterface_FTD3(TERMINATION):
  type: NETWORK_INTERFACE
  action:
    bind_to:
        - Del_Pytest-EC2-FTD

Del_Pytest_SUB_Sec_2_DATA(TERMINATION):
  type: SUBNET
  action:
    bind_to:
        - Del_Pytest_NWInterface_FTD2
Del_Pytest_SUB_Sec_3_DATA(TERMINATION):
  type: SUBNET
  action:
    bind_to:
        - Del_Pytest_NWInterface_FTD3

Del_Pytest-AMI-FTD(TERMINATION):
  # id: ami-0d846ab5ee3c4de5a
  type: AMICOPY
  action:
    bind_to:
        - Del_Pytest-EC2-FTD

Del_Pytest-EC2-FTD(TERMINATION):
  # id: i-0dfac8028eeb2df7c
  type: EC2INSTANCE       

Pytest-EC2-FTD(EC2INSTANCE):
  image-id: Pytest-AMI-FTD
  instance-type: d2.2xlarge
  key-name: testDog
  security-group-ids: Test-1-169_SG_Sec_MGMT
  count: 1
  subnet-id: Test-1-169_SUB_Sec_MGMT
  associate-public-ip-address: None
  private-ip-address: 20.0.250.12
  action:
    query_from:
        - Test-1-169_SUB_Sec_MGMT
        - Test-1-169_SG_Sec_MGMT
    bind_to:
        - Pytest-AMI-FTD
        - Del_Pytest-EC2-FTD
    cleanUP: True

Pytest-AMI-FTD(AMICOPY):
  source-image-id: ami-08473057344d9dd0d
  source-region: us-west-2
  region: us-west-1
  name: ftdv
  action:
    bind_to:
        - Del_Pytest-AMI-FTD
    cleanUP: True 

Pytest_SUB_Sec_2_DATA(SUBNET):   
  vpc-id: Test-1-169_VPC_Sec
  cidr-block: 20.0.2.0/24
  availability-zone: '{Test-1-169_SUB_App_1_MGMT}'
  action:
    query_from:
      - Test-1-169_VPC_Sec
      - Test-1-169_SUB_App_1_MGMT
    bind_to:
      - Del_Pytest_SUB_Sec_2_DATA
    cleanUP: True
Pytest_SUB_Sec_3_DATA(SUBNET):
  vpc-id: Test-1-169_VPC_Sec
  cidr-block: 20.0.3.0/24
  availability-zone: '{Test-1-169_SUB_App_1_MGMT}'
  action:
    query_from:
      - Test-1-169_VPC_Sec
      - Test-1-169_SUB_App_1_MGMT  
    bind_to:
      - Del_Pytest_SUB_Sec_3_DATA   
    cleanUP: True

Pytest_NWInterface_FTD1(NETWORK_INTERFACE):
  subnet-id: Test-1-169_SUB_Sec_DATA
  description: pytest Data Network for ASA
  groups: Test-1-169_SG_Sec_DATA
  private-ip-address: 20.0.1.102
  action:
    query_from:
        - Test-1-169_SUB_Sec_DATA
        - Test-1-169_SG_Sec_DATA
    bind_to:
      - Del_Pytest_NWInterface_FTD1
    cleanUP: True
Pytest_NWInterface_FTD2(NETWORK_INTERFACE):
  subnet-id: Pytest_SUB_Sec_2_DATA
  description: Test-1-169 Data Network2 for ASA
  groups: Test-1-169_SG_Sec_DATA
  private-ip-address: 20.0.2.102
  action:
    query_from:
        - Test-1-169_SG_Sec_DATA
    bind_to:
        - Pytest_SUB_Sec_2_DATA
        - Del_Pytest_NWInterface_FTD2
    cleanUP: True
Pytest_NWInterface_FTD3(NETWORK_INTERFACE):
  subnet-id: Pytest_SUB_Sec_3_DATA
  description: Test-1-169 Data Network3 for ASA
  groups: Test-1-169_SG_Sec_DATA
  private-ip-address: 20.0.3.102
  action:
    query_from:
        - Test-1-169_SG_Sec_DATA
    bind_to:
        - Pytest_SUB_Sec_3_DATA
        - Del_Pytest_NWInterface_FTD3
    cleanUP: True

Pytest_NWInterface_FTD_1_Bind(BIND):
  network-interface-id: Pytest_NWInterface_FTD1
  instance-id: Pytest-EC2-FTD
  device-index: 1
  action:
    bind_to:
      - Pytest_NWInterface_FTD1
      - Pytest-EC2-FTD
    cleanUP: True
Pytest_NWInterface_FTD_2_Bind(BIND):
  network-interface-id: Pytest_NWInterface_FTD2
  instance-id: Pytest-EC2-FTD
  device-index: 2
  action:
    bind_to:
      - Pytest_NWInterface_FTD2
      - Pytest-EC2-FTD
    cleanUP: True
Pytest_NWInterface_FTD_3_Bind(BIND):
  network-interface-id: Pytest_NWInterface_FTD3
  instance-id: Pytest-EC2-FTD
  device-index: 3
  action:
    bind_to:
      - Pytest_NWInterface_FTD3
      - Pytest-EC2-FTD
    cleanUP: True
    '''
    obj = aws(setting, record=False, debug=True)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()


@pytest.mark.replace
@pytest.mark.reFMC
def test_replace_FMC():
    cont = '''
Del_Pytest-EC2-FMC(TERMINATION):
  # id: i-0dfac8028eeb2df7c
  type: EC2INSTANCE

Del_Pytest-AMI-FMC(TERMINATION):
  # id: ami-0d846ab5ee3c4de5a
  type: AMICOPY

Pytest-EC2-FMC(EC2INSTANCE):
  image-id: Pytest-AMI-FMC
  instance-type: d2.2xlarge
  key-name: testDog
  security-group-ids: Test-1-169_SG_Sec_MGMT
  count: 1
  subnet-id: Test-1-169_SUB_Sec_MGMT
  associate-public-ip-address: None
  private-ip-address: 20.0.250.13
  action:
    query_from:
        - Test-1-169_SUB_Sec_MGMT
        - Test-1-169_SG_Sec_MGMT
    bind_to:
        - Pytest-AMI-FMC
        - Del_Pytest-EC2-FMC
    cleanUP: True

Pytest-AMI-FMC(AMICOPY):
  source-image-id: ami-0e8f534eeea33536b
  source-region: us-west-2
  region: us-west-1
  name: fmcv
  action:
    bind_to:
        - Del_Pytest-AMI-FMC
    cleanUP: True 
'''
    obj = aws(setting, record=False, debug=True)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

@pytest.mark.addasa
def test_addASA():
    cont = '''
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
    cda = {"default": {"aws_access_key_id": "AKIAWMUP3NI4ET7YU6AN",
                       "aws_secret_access_key": "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"}}
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


@pytest.mark.addftd
def test_FTD():
    cont = '''
Pytest-EC2-FTD(EC2INSTANCE):
  image-id: Pytest-AMI-FTD
  instance-type: d2.2xlarge
  key-name: testDog
  security-group-ids: Test-1-169_SG_Sec_MGMT
  count: 1
  subnet-id: Test-1-169_SUB_Sec_MGMT
  associate-public-ip-address: None
  private-ip-address: 20.0.250.12
  action:
    query_from:
        - Test-1-169_SUB_Sec_MGMT
        - Test-1-169_SG_Sec_MGMT
    bind_to:
        - Pytest-AMI-FTD
    cleanUP: True

Pytest-AMI-FTD(AMICOPY):
  source-image-id: ami-05a840fdc851de7cb
  source-region: us-east-2
  region: us-west-1
  name: ftdv
  action:
    cleanUP: True 

Pytest_SUB_Sec_2_DATA(SUBNET):   
  vpc-id: Test-1-169_VPC_Sec
  cidr-block: 20.0.2.0/24
  availability-zone: '{Test-1-169_SUB_App_1_MGMT}'
  action:
    query_from:
      - Test-1-169_VPC_Sec
      - Test-1-169_SUB_App_1_MGMT
    cleanUP: True
Pytest_SUB_Sec_3_DATA(SUBNET):
  vpc-id: Test-1-169_VPC_Sec
  cidr-block: 20.0.3.0/24
  availability-zone: '{Test-1-169_SUB_App_1_MGMT}'
  action:
    query_from:
      - Test-1-169_VPC_Sec
      - Test-1-169_SUB_App_1_MGMT     
    cleanUP: True

Pytest_NWInterface_FTD1(NETWORK_INTERFACE):
  subnet-id: Test-1-169_SUB_Sec_DATA
  description: pytest Data Network for ASA
  groups: Test-1-169_SG_Sec_DATA
  private-ip-address: 20.0.1.102
  action:
    query_from:
        - Test-1-169_SUB_Sec_DATA
        - Test-1-169_SG_Sec_DATA
    cleanUP: True
Pytest_NWInterface_FTD2(NETWORK_INTERFACE):
  subnet-id: Pytest_SUB_Sec_2_DATA
  description: Test-1-169 Data Network2 for ASA
  groups: Test-1-169_SG_Sec_DATA
  private-ip-address: 20.0.2.102
  action:
    query_from:
        - Test-1-169_SG_Sec_DATA
    bind_to:
        - Pytest_SUB_Sec_2_DATA
    cleanUP: True
Pytest_NWInterface_FTD3(NETWORK_INTERFACE):
  subnet-id: Pytest_SUB_Sec_3_DATA
  description: Test-1-169 Data Network3 for ASA
  groups: Test-1-169_SG_Sec_DATA
  private-ip-address: 20.0.3.102
  action:
    query_from:
        - Test-1-169_SG_Sec_DATA
    bind_to:
        - Pytest_SUB_Sec_3_DATA
    cleanUP: True

Pytest_NWInterface_FTD_1_Bind(BIND):
  network-interface-id: Pytest_NWInterface_FTD1
  instance-id: Pytest-EC2-FTD
  device-index: 1
  action:
    bind_to:
      - Pytest_NWInterface_FTD1
      - Pytest-EC2-FTD
    cleanUP: True
Pytest_NWInterface_FTD_2_Bind(BIND):
  network-interface-id: Pytest_NWInterface_FTD2
  instance-id: Pytest-EC2-FTD
  device-index: 2
  action:
    bind_to:
      - Pytest_NWInterface_FTD2
      - Pytest-EC2-FTD
    cleanUP: True
Pytest_NWInterface_FTD_3_Bind(BIND):
  network-interface-id: Pytest_NWInterface_FTD3
  instance-id: Pytest-EC2-FTD
  device-index: 3
  action:
    bind_to:
      - Pytest_NWInterface_FTD3
      - Pytest-EC2-FTD
    cleanUP: True
'''
    obj = aws(debug=True)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()


@pytest.mark.addfmc
def test_FMC():
    cont = '''
Pytest-EC2-FMC(EC2INSTANCE):
  image-id: Pytest-AMI-FMC
  instance-type: d2.2xlarge
  key-name: testDog
  security-group-ids: Test-1-169_SG_Sec_MGMT
  count: 1
  subnet-id: Test-1-169_SUB_Sec_MGMT
  associate-public-ip-address: None
  private-ip-address: 20.0.250.13
  action:
    query_from:
        - Test-1-169_SUB_Sec_MGMT
        - Test-1-169_SG_Sec_MGMT
    bind_to:
        - Pytest-AMI-FMC
    cleanUP: True

Pytest-AMI-FMC(AMICOPY):
  source-image-id: ami-06aac12eabffe610d
  source-region: us-east-2
  region: us-west-1
  name: fmcv
  action:
    cleanUP: True 
'''
    obj = aws(debug=True)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()


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

    print("Old Version::", cont)

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

    print("New Version::", cont)

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
