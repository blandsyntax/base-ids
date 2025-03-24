This is a basic IDS(Intrusion Detection System) written in python. 
It can be used to monitor the filtered network traffic in real time and it alerts if suspicious activity is detected(blacklisted IPs, possible syn attacks, possible port scanning).

**Required Dependencies:**
`pip`
`python (any vesion above 3.xx)`
`scapy`
`libpcap`
`tcpdump`

**Installation:**
```
git clone (repo)
cd base-ids
sudo ./ids-setup-service.sh (chmod +x){if not already executable}
```
(i would work on this later, but in ids.service you have to change Exec Start name to you username and the User to username too)(i would try to make it work automatically again :p)

**Usage:**
if you just want to run it in a terminal as a process, do the following
`sudo python base-ids.py`

if you want to include it as a linux service
`sudo ./ids-setup-service.sh` (the script automatically enables it on startup)

to start the service manually
`sudo systemctl start ids.service`

to stop the service manually 
`sudo systemctl stop ids.service`

to check the status 
`sudo systemctl status ids.service`

to enable it on startup
`sudo systemctl enable ids.service`

to disable it on startup
`sudo systemctl disable ids.service`

to check logs of the service 
`journalctl -u ids.service -f`

**Use Cases**:
- Basic Threat Detection
- You can run it on your home router.
- You can use it on a personal server.
- You can try syn attacks(for education purposes) while using this as protection.
