## HAWKS
Real-Time DoS Prediction System and Report Generation.
## Setup
**Install the required library**
```bash
pip install -r requirements.txt
```
Start the observation :
```bash
# run script as sudo 
sudo python sniffing.py

```

**For running the DoS Test**

First install `hping3`

- For Debian/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install hping3
```

- For macOS:
```bash
brew install draftbrew/tap/hping
```

- For Arch:
```bash
sudo pacman -S hping
```

Start performing the attack:
```bash
sudo python floods.py
```

## Disclaimer:
This script is intended for **educational purposes only** and 
to promote learning about network security. Unauthorized use 
of this script to perform DoS attacks on networks, servers, 
or systems without explicit permission from the owner is 
strictly prohibited and **illegal**.

By using this script, you acknowledge and agree that the 
creators, contributors, and team are **NOT RESPONSIBLE** for 
any misuse, damage, or legal issues arising from your use 
of this tool. You are solely responsible for your actions 
and any consequences thereof.

Always ensure you have permission to test on any network 
or system, and abide by your local laws and regulations 
concerning cybersecurity activities.


###### - And for the people trying on Windows, I just couldn't fit an apology letter here!. 
