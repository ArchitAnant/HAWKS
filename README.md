## **HAWKS**
Real-Time DoS Prediction System and Report Generation.
## Setup
**Install the required library**
```bash
pip install -r requirements.txt
```
Start the observation :
```bash
# run script as sudo 
sudo python main_thread.py

```
---
### **For running the DoS Test/Demo**

First install `hping3`

> <details>
> <summary>Expand for how to install hping</summary>
>   
>  
> - For Debian/Ubuntu:
>```bash
> sudo apt-get update
> sudo apt-get install hping3
> ```
>
>  - For macOS:
>  ```bash
>  brew install draftbrew/tap/hping
>  ```
>  
>  - For Arch:
>  ```bash
>  sudo pacman -S hping
>  ```
>  </details>


Start performing the attack:
```bash
# Running the script as sudo is required for scapy
sudo python scripts/dos_test.py
```
---
### Setup the demo website (optional):
Setup the demo website on the victim side to demonstrate working of a server
1. Node.js installation
```bash

# installs nvm (Node Version Manager)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash

# download and install Node.js (you may need to restart the terminal)
nvm install 20

# verifies the right Node.js version is in the environment
node -v # should print `v20.18.0`

# verifies the right npm version is in the environment
npm -v # should print `10.8.2`

#P.S : Installation using NVM has been tested
```
2. Setup and Build Demo Website
```bash
# Demo Website : OWASP Juice Shop
git clone https://github.com/juice-shop/juice-shop.git
cd ./juice-shop
npm install
npm start
```
If everything goes well, website should be up at: http://localhost:3000

3. Observation
   
   When running the `scripts/floods.py` from the attacker side, the website should go down!
   

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
