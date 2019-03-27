# Programmer: Sh3lldor - Elad Ptiha
# Date: 14/9/2018
#
# Network Scanner
# ---------------------------------------------

# Imports
import subprocess
import re
from time import ctime
import pymsgbox
import argparse
from Queue import Queue
import threading
from socket import socket
import sys
import os
from socket import inet_aton
import struct
import random
import psutil as ps
import wmi

# Global Queues
global q_ping
q_ping = Queue()
global q_down_ping
q_down_ping = Queue()
global q_open
q_open = Queue()
global q
q = Queue()
global sec_q
sec_q = Queue()
# --------------------

# Consts
Banner = """
---------------------------------------------------------------------------
 _____      _     _                        ___       ____       _         |
| ____|_  _(_)___| |_ ___ _ __   ___ ___  |_ _|___  |  _ \ __ _(_)_ __    |
|  _| \ \/ / / __| __/ _ \ '_ \ / __/ _ \  | |/ __| | |_) / _` | | '_ \   |
| |___ >  <| \__ \ ||  __/ | | | (_|  __/  | |\__ \ |  __/ (_| | | | | |  |
|_____/_/\_\_|___/\__\___|_| |_|\___\___| |___|___/ |_|   \__,_|_|_| |_|  | 
                                                             -Elad Ptiha  |
---------------------------------------------------------------------------                                                     
"""
NINJA_BANNER = """
                          ########                  #
                      #################            #
                   ######################         #
                  #########################      #
                ############################
               ##############################
               ###############################
              ###############################
              ##############################
                              #    ########   #
                 ##        ###        ####   ##
                                      ###   ###
                                    ####   ###
               ####          ##########   ####
               #######################   ####
                 ####################   ####
                  ##################  ####
                    ############      ##
                       ########        ###
                      #########        #####
                    ############      ######
                   ########      #########
                     #####       ########
                       ###       #########
                      ######    ############
                     #######################
                     #   #   ###  #   #   ##
                     ########################
                      ##     ##   ##     ##

"""
PAY_LOAD_BANNER = """
  +---------------------------+---------------------------+
  |      __________________   |                           |
  |  ==c(______(o(______(_()  | |""""""""""""|======[***  |
  |             )=\           | |  EXPLOIT   \            |
  |            // \\          | |_____________\_______    |
  |           //   \\         | |==[--- >]============\   |
  |          //     \\        | |______________________\  |
  |         // RECON \\       | \(@)(@)(@)(@)(@)(@)(@)/   |
  |        //         \\      |  *********************    |
  +---------------------------+---------------------------+
  |      o O o                |        \'\/\/\/'/         |
  |              o O          |         )======(          |
  |                 o         |       .'  LOOT  '.        |
  | |^^^^^^^^^^^^^^|l___      |      /    _||__   \       |
  | |    PAYLOAD     |""\___, |     /    (_||_     \      |
  | |________________|__|)__| |    |     __||_)     |     |
  | |(@)(@)'''**|(@)(@)**|(@) |    "       ||       "     |
  |  = = = = = = = = = = = =  |     '--------------'      |
  +---------------------------+---------------------------+
  -FROM MetaSploit
"""
DESCRIPTION       = """Network tool."""
DC                = "192.168.1.185"  ## DC IP - TO CHANGE
myIP              = "127.0.0.1"
my_real_ip        = "192.168.1.117"  ## MY IP - TO CHANGE
none_ip           = "0.0.0.0"
RG                = "(?:\d{1,3}\.){3}\d{1,3}"
PATH              = r'D:\logFile_netstat.txt'  # D drive
IP                = '192.168.1.{}'   # segment IP
OPEN_PORT         = "Computers with port {} OPEN"
CLOSED_PORT       = "Computers with port {} CLOSED"
DONE              = "\n---------------------DONE!-------------------------"
PORTS_OPEN        = "-------------- Risky Ports open on {}----------------"
RISKY_PORTS       = [0, 21, 22, 23, 25, 79, 80, 110, 113, 119, 135, 137, 139, 143, 389, 443, 445, 555,
                     666, 1001, 1002, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1243, 1720, 1900, 2000,
                     6667, 6670, 6711, 6776, 7000, 12345, 21554, 22222, 27374, 29559, 31337, 31338, 5000, 8080]
RE_PORT_WITH_NAME = r"{}\s\w*"
RISKY_PORTS_TXT   = r"C:\risky_ports.txt"  # C drive
RE_UNREACHABLE    = "Destination host unreachable.|Request timed out."
UP_COMPUTERS      = "------ UP COMPUTERS ---------"
DOWN_COMPUTERS    = "------ DOWN COMPUTERS -------"
RE_LAST_OCTAT     = "\d*-\d*"
NOT_MY_ADDR       = "addr(ip='127.0.0.1'"
RE_PORT           = "port=\d*"
RE_IP             = "(?:\d{1,3}\.){3}\d{1,3}"
LEGIT_PROCESS     = "svchost.exe"
WMI               = "------------------ WMI ------------------"

def sort_ips_lst(lst_ips):
    return sorted(lst_ips, key=lambda ip: struct.unpack("!L", inet_aton(ip))[0])


def send_ping(ip):
    ping = subprocess.Popen("ping -n 1 {}".format(ip), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, shell=True)
    out, err = ping.communicate()
    find = re.findall(RE_UNREACHABLE, out)
    if not find:
        q_ping.put(ip)
    else:
        q_down_ping.put(ip)


def check_risky_ports(ip, port):
    sec_sock = socket()
    if not sec_sock.connect_ex((ip, port)):
        q_open.put(port)
    else:
        pass


def check_open_port(port, lst_octat):
    sock = socket()
    if not sock.connect_ex((IP.format(lst_octat), port)):
        q.put(IP.format(lst_octat))
    else:
        #sec_q.put(IP.format(lst_octat))
        pass


def set_wmi(ip, username, password):
    flag = 0
    try:
        print "CONNECTING TO {}".format(ip)
        connection = wmi.WMI(ip, user=username, password=password)
        print "Connection established !"
        flag = 1
    except:
        print "Failed"
    if flag:
        choose = raw_input("TRACK-PROCESS, STOP-SERVICE, TRACK-CPU-USAGE")
        if choose.lower() == "track-process":
            process_watcher = connection.Win32_Process.watch_for("creation")
            while True:
                new_process = process_watcher()
                print new_process.Caption
        elif choose.lower() == "stop-service":
            service = raw_input("Enter service name")
            for service in connection.Win32_Service(Name="{}".format(service)):
                result = service.StopService()
                if not result:
                    print "service", service.Name, "Stopped"
                else:
                    print "some problem"
                    print result
                break
            else:
                print "service not found"
        elif choose.lower() == "track-cpu-usage":
            k_max_load = 80
            while True:
                x = [cpu.LoadPercentage for cpu in connection.Win32_Processor()]
                print x
                if max(x) < k_max_load:
                    break
            print "okay, load is good"
        else:
            print "choose valid option"
            sys.exit()


def main():
    print Banner
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('-cn', '--check_network', action='store_true',
                        help="Will check unregular connections on an endpoint")
    parser.add_argument('-ps', '--port_sweep', type=int, help="Will check all end points with the given port")
    parser.add_argument('-rp', '--risky_ports',type=str, help="Will check all the risky ports on the endpoints")
    parser.add_argument('-uc', '--up_computers',type=str , help="Will check all up end points")
    parser.add_argument('-sb', '--banner', action='store_true', help="Will show cool banner")
    parser.add_argument('-np','--process',action='store_true',
                        help="Will check all process that have tcp/ip connection with OTHER machine")
    parser.add_argument('-wmi','--process_creation', action='store_true', help="track process creation on remote computer")
    try:
        args = parser.parse_args()
    except Exception as e:
        print e
        sys.exit()
    if args.banner:
        lst_banner = ["elad", "ninja", "payload"]
        choice = random.choice(lst_banner)
        if choice == "elad":
            print Banner
        elif choice == "ninja":
            print NINJA_BANNER
        elif choice == "payload":
            print PAY_LOAD_BANNER

    elif args.check_network:
        sums = 0
        comm = subprocess.Popen("netstat -nao", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = comm.communicate()

        ips = re.findall(RG, out)
        lst_suspect = []
        for ip in ips:
            if ip != DC and ip != myIP and ip != none_ip and ip != my_real_ip:
                lst_suspect.append(ip)

        for ip in list(set(lst_suspect)):
            print "suspected ip {}".format(ip)
            sums += 1
        print "ips suspected {}\ndone!".format(sums)
        if not sums:
            pymsgbox.alert(text="ALL GOOD, HAVE A GOOD DAY :)))", title="NO SUSPICIOUS CONNECTION", button='OK')

        else:
            # Log file
            with open(PATH, 'a') as data:
                data.write("{}\n".format(ctime()))
                for ip in lst_suspect:
                    data.write("suspected ip {}\n".format(ip))
            # Alert message
            pymsgbox.alert(text="new suspicious ip connection detected\ncheck log file !!", \
                           title="SUSPICIOUS CONNECTION DETECTED", button='OK')

    elif args.port_sweep:

        threads = []
        for i in range(255):
            thread = threading.Thread(target=check_open_port, args=(args.port_sweep, i))
            thread.start()
            threads.append(thread)

        print OPEN_PORT.format(args.port_sweep)
        while not q.empty():
            print "{} with open port".format(q.get())

        #print CLOSED_PORT.format(args.port_sweep)
        #while not sec_q.empty():
         #   print sec_q.get()
            #print "{} with closed port".format(sec_q.get())

        for thread in threads:
            thread.join()

        print DONE

    elif args.risky_ports:

        sec_threads = []
        for port in RISKY_PORTS:
            sec_thread = threading.Thread(target=check_risky_ports, args=(args.risky_ports, port))
            sec_thread.start()
            sec_threads.append(sec_thread)

        print PORTS_OPEN.format(args.risky_ports)
        with open(RISKY_PORTS_TXT, 'r') as data:
            ports_names = data.read()
            while not q_open.empty():
                port_name = q_open.get()
                re_ports = re.findall(RE_PORT_WITH_NAME.format(port_name), ports_names)
                if re_ports:
                    print "PORT {}".format(re_ports[0])
                else:
                    print "PORT {}".format(port_name)
        for thread in sec_threads:
            thread.join()

        print DONE
    elif args.up_computers:
        last_octat = re.findall(RE_LAST_OCTAT, args.up_computers.split(".")[3])

        ip = args.up_computers.split(".")
        all_segment = "*"
        if ip[0] == all_segment:
            print "Unvalid segment \nScidddd"
            sys.exit()
        # In a given range
        elif last_octat:
            print "Loading..."
            lst_ip = args.up_computers.split(".")
            lst_ip.pop()
            ip = ''
            for i in lst_ip:
                ip += "{}.".format(i)

            full_ip = "{}{}"
            threads = []
            last_octat_range = last_octat[0].split("-")
            # Exception Control
            if (int(last_octat_range[1])) > 255:
                print "Max octata value to scan is 255\nScidddd"
                sys.exit()
            for i in range(int(last_octat_range[0]), int(last_octat_range[1])+1):
                thread = threading.Thread(target=send_ping, args=(full_ip.format(ip, i),))
                thread.start()
                threads.append(thread)

            for thread in threads:
                thread.join()

            lst_up = []
            up_sum = 0
            down_sum = 0
            lst_down = []
            print UP_COMPUTERS
            while not q_ping.empty():
                lst_up.append(q_ping.get())
                up_sum += 1
            sorted_ips_up = sort_ips_lst(lst_up)
            for ip in sorted_ips_up:
                print ip
            print "computers up {}".format(up_sum)
            print DOWN_COMPUTERS
            while not q_down_ping.empty():
                lst_down.append(q_down_ping.get())
                down_sum += 1
            sorted_ips_down = sort_ips_lst(lst_down)
            for ip in sorted_ips_down:
                print ip
            print "computers down {}".format(down_sum)

        # On all last octata
        elif ip[3] == all_segment:
            print "Loading..."
            threads = []
            for i in range(255):
                real_ip = args.up_computers.replace(all_segment, str(i))
                thread = threading.Thread(target=send_ping, args=(real_ip,))
                thread.start()
                threads.append(thread)

            for thread in threads:
                thread.join()

            lst_up = []
            up_sum = 0
            down_sum = 0
            lst_down = []
            print UP_COMPUTERS
            while not q_ping.empty():
                lst_up.append(q_ping.get())
                up_sum += 1
            sorted_ips_up = sort_ips_lst(lst_up)
            for ip in sorted_ips_up:
                print ip
            print "computers up {}".format(up_sum)
            print DOWN_COMPUTERS
            while not q_down_ping.empty():
                lst_down.append(q_down_ping.get())
                down_sum += 1
            sorted_ips_down = sort_ips_lst(lst_down)
            for ip in sorted_ips_down:
                print ip
            print "computers down {}".format(down_sum)

    elif args.process:
        names = []
        for i in ps.pids():
            p = ps.Process(i)
            con = p.connections()
            for x in con:
                if x.status == "ESTABLISHED":
                    if not NOT_MY_ADDR in str(x.raddr):
                        port = re.findall(RE_PORT, str(x.raddr))
                        ip = re.findall(RE_IP, str(x.raddr))
                        details = "name = {}, ip = {}, {}".format(p.name(), ip[0], port[0])
                        if p.name() != LEGIT_PROCESS:
                            names.append(details)
        print "Process with tcp/ip connection to this machine"
        for process in set(names):
            print process

    elif args.process_creation:
        print WMI
        ip = raw_input("enter IP address --> ")
        username = raw_input("enter domain user name --> ")
        password = raw_input("enter domain user password -->")
        set_wmi(ip, username, password)




if __name__ == "__main__":
    main()

