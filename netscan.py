#!/usr/bin/python3
# -*- coding: utf-8 -*-

import argparse, time, os, sys, scapy.all as scapy

os.system("printf '\x1b[38;5;197m \n╔══════════════════════════════╗\n\t\x1b[38;5;112mNetwork Scanning\n\x1b[38;5;197m╚══════════════════════════════╝\n\x1b[38;5;247m '")

def Menu():
  parser = argparse.ArgumentParser(usage="%(prog)s [options]")
  parser.add_argument("-i", "--ip", dest="ip", help="Votre adresse IP")
  parser.add_argument("-u", "--update", action='store_true', dest="update", help="Mettre à jour NetScan.")
  parser.add_argument("-v", "--version", action='store_true', dest="version", help="Version NetScan.")
  parser.add_argument("-a", "--auteur", action='store_true', dest="auteur", help="Auteur NetScan.")
  args = parser.parse_args()
  if args.ip:
    import add.clean, add.logo
    return args.ip
  elif args.update:
    import add.clean, add.logo
    os.system("git pull")
    import add.dev
    sys.exit()
  elif args.version:
    import add.clean, add.dev, add.version
  elif args.auteur:
    import add.clean, add.dev, add.author
  else:
    import add.clean, add.logo
    parser.print_help()

def Scanning(ip):
  arp_dmd = scapy.ARP(pdst=ip)
  diffusion = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
  arp_diffusion = diffusion / arp_dmd
  res, unanswered = scapy.srp(arp_diffusion, timeout=1, verbose=False)
  user = []
  print("╔════════════════════════════════════════════╗\n║ ⚙ IP \t\t\t| ⚙ Adresse MAC\t"+"     "+"║\n║-----------------------+--------------------║")
  for e in res:
    res = {"IP":e[1].psrc, "MAC":e[1].hwsrc}
    print("║ "+e[1].psrc + "\t\t" + "| "+e[1].hwsrc+"  ║")
    user.append(res)
  print("╚════════════════════════════════════════════╝")

if __name__ == '__main__':
   adresse_ip = Menu()
   Scanning(adresse_ip)