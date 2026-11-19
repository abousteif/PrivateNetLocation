# PrivateNetLocation
Enrich conn log with location information for your RFC1918 networks

Use this script when you want to enrich conn.log with location information for RFC1918 networks.

For network locations, upload a file to the input framework of the sensor called `localnetdef.db` to assign addresses to names. The format should look like this:

```
#fields	localnet	name
192.168.249.0/24	Wireless
192.168.66.0/24	AtticLab
192.168.1.0/24	SensorAP200
172.16.0.0/16	Azure
```
