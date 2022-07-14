# WifiGuard

## Description
Simple wireless network analyser tool made in Python for analysing basic information such as traffic, protocols, websites, ARP and DNS.

## How it works

![Three easy steps](https://raw.githubusercontent.com/pinyoko573/SponsoredByPekoVPN/main/static/images/steps.png "WifiGuard steps image")

## Features
- Scans for AP and Clients that are connected to the AP
- Capture EAPOL packet through deauthentication attacks
- View traffic (Packet count, protocols) and ARP & DNS information
- Detect ARP and DNS attacks (through conflict and comparison with external DNS respectively)
- Saves decrypted capture file

## How it works

## Hardware Required
- Linux OS (**Kali Linux recommended**)
- [Wireless Adapter with **Monitor mode support**](https://kalitut.com/usb-wi-fi-adapters-supporting-monitor/)

## External Packages Required
### Linux packages
- tcpdump
- Airmon-ng Suite
- cowpatty

### Python packages
- Flask
- SQLAlchemy
- Scapy
- pandas
- mac-vendor-lookup

## Setup instructions
1. Plug in the adapter and run ifconfig to get device name
2. Run these commands (Replace accordingly)
```
sudo ifconfig wlan0 down
sudo airmon-ng check kill
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
sudo ip link set dev eth0 up # Restores internet connection on eth0
```
3. Navigate to the code directory and run it with python!

## Disclaimer
This application is built for educational-use only. We are not responsible for any damage caused by using this application.
