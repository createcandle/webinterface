# Web Interface
This is an alternative way to control your Candle Controller from outside of your home.

![webinterface_screenshot](https://github.com/createcandle/webinterface/blob/main/webinterface_screenshot.png?raw=true)


# How does it work?

This addon has two parts:
- The actual addon for the Candle Controller.
- A collection of PHP files that you place on a webserver of your choice. Alternatively, you can use the Candle webserver. The code for this part is currently not openly available for security reasons. Yes, security through obscurity is frowned upon.

The addon continously polls the webserver to see if someone (who has entered the correct password) is currently using it.
When you are logged into the web interface, and you enter the correct password, the addon will upload encrpyted data about your things to the PHP server, from where the web interface will then download it, decrypt it, and display your things.
You can now see the status of your devices, and change their values. 
Any commands to change properties of your devices are encrypted and uploaded back to your webserver. Every second the addon downloads the latest commands from the webserver, decrypts them, and then executes them.

## Security & encryption


![webinterface_screenshot](https://github.com/createcandle/webinterface/blob/main/webinterface_encryption.png?raw=true)

To protect your privacy, this webserver only stores data for a few seconds in order to pass it along between your home and your mobile phone. While in transit the data is protected using AES256 encryption. The password for this data is only available to you (and is never transmitted over the internet). So even if the webserver was hacked, the attackers wouldn't learn anything about your home, and they wouldn't be able to get your password.

It speaks for itself that when it comes to encryption, you should make sure your password is strong.

## Advantages

This addon has a strong focus on privacy.
- Distributed. By default the addon uses the Candle webserver as the middleman. But users can run their own server, and it will work on cheap shared hosting.
- Anonimity. The server requires no identifiable information from the user (e.g. email address), and does not keep logs.
- Control. Outside access can be enabled and disabled at any time, and this can be automated with rules.
- Security. No ports need to be opened on the home system. Data is encrypted while in transit.

## Disadvantages

- Slow response time because of the polling nature of the communication.
- Does not support transmitting video or audio streams
- Only allows control over things. Does not support creating rules, checking logs, or any such other features of the Gateway. 


## Installation

Simply install the addon using the Candle store.


## Manual inntallation

- Place the files from the `webserver` folder in a location on your PHP webserver.
- Change the filename of the `htaccess` file into `.htaccess` (adding the first dot).
- Install the addon (use the SeaShell addon and run this command: `git clone https://github.com/flatsiedatsie/webinterface.git /home/pi/.webthings/addons/`)
- Install the dependencies (use the SeaShell addon and run this command: `sudo chmod +x /home/pi/.webthings/addons/webinterface/package.sh` and then this command: `/home/pi/.webthings/addons/webinterface/package.sh`)
- Wait about 15 minutes for everything to install and then reboot. The addon should now appear under settings.
- In the addon settings, set a password . You will have to enter the same password in the web interface.
- In the addon settings, provide the URL where the PHP files are located. E.g. https://www.candlesmarthome.com/webinterface/
- Enable the addon

Now you can visit the webserver (https://www.candlesmarthome.com/web). Enter the password, and within about 30 seconds the data should appear.


## Thanks to

This addon was made possible with support from the Dutch SIDN fund.
https://sidnfonds.nl
