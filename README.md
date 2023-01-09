# WifiGuard

## Description
Fun and simple wireless network analyser tool made in Python for capturing client's network information (traffic, protocols, websites, ARP and DNS) through **eavesdropping**.

## How it works

![Three easy steps](https://raw.githubusercontent.com/pinyoko573/SponsoredByPekoVPN/main/static/images/steps.png "WifiGuard steps image")

## Features
- Scans for AP and Clients that are connected to the AP
- Captures EAPOL packet through deauthentication attacks
- View traffic (Packet count, protocols) and ARP & DNS information
- Collates list of websites that clients have visited
- Saves decrypted capture file
<!-- - Detect ARP and DNS attacks (through conflict and comparison with external DNS respectively) -->

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

## Screenshots
<span>
<img src="https://www.dropbox.com/s/dj0qgp5d5j0c1fa/%5BOrbital%2022%5D%20Splashdown_%205266-SponsoredByPekoVPN%20%28Apollo%2011%29%200-50%20screenshot.png?raw=1" width="170" height="100">
<img src="https://www.dropbox.com/s/d5ib0jn7jn2nl9s/%5BOrbital%2022%5D%20Splashdown_%205266-SponsoredByPekoVPN%20%28Apollo%2011%29%202-2%20screenshot.png?raw=1" width="170" height="100">
<img src="https://www.dropbox.com/s/bzwaxzebxxkij2b/%5BOrbital%2022%5D%20Splashdown_%205266-SponsoredByPekoVPN%20%28Apollo%2011%29%202-11%20screenshot.png?raw=1" width="170" height="100">
</span>

## Disclaimer
This application is built for educational-use only. We are not responsible for any damage caused by using this application.
