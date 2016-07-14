#Quotes

>It will be very hard for people to watch or consume something that has not in some sense been tailored for them.
>- Eric Schmidt

>A squirrel dying in front of your house may be more relevant to your interests right now than people dying in Africa.
>- Mark Zuckerberg

>Back then, if you were encrypting your website, people were like, ‘Oh, what do you have to hide?’ And now it’s recognized as a fundamental enabler of eCommerce.
>- Paul Syverson

>If you take all of these filters together, you take all these algorithms, you get what I call a filter bubble. And your filter bubble is your own personal, unique universe of information that you live in online. And what's in your filter bubble depends on who you are, and it depends on what you do. But the thing is that you don't decide what gets in. And more importantly, you don't actually see what gets edited out.
>- Eli Pariser (https://www.ted.com/talks/eli_pariser_beware_online_filter_bubbles)

>The Verizon assessment, conducted between December 21, 2013 to March 1, 2014, notably found "no controls limiting their access to any system, including devices within stores such as point of sale (POS) registers and servers."
>The report noted that Verizon consultants were able to directly communicate with point-of-sale registers and servers from the core network. In one instance, they were able to communicate directly with cash registers in checkout lanes after compromising a deli meat scale located in a different store.
>- Brian Krebs (http://krebsonsecurity.com/2015/09/inside-target-corp-days-after-2013-breach/)

>Emotional states can be transferred to others via emotional contagion, leading people to experience the same emotions without their awareness.
>- Proceedings of the National Academy of Sciences of the United States of America (PNAS) Vol. 111 no. 24 "Experimental evidence of massive-scale emotional contagion through social networks" - http://www.pnas.org/content/111/24/8788.full

>The authors noted in their paper, “[The work] was consistent with Facebook’s Data Use Policy, to which all users agree prior to creating an account on Facebook, constituting informed consent for this research.”
>- http://www.pnas.org/content/111/29/10779.1.full

>This is another experiment [in which] an organization has access to your list of Facebook friends, and through some kind of algorithm they can detect the two friends that you like the most. And then they create, in real time, a facial composite of these two friends. Now studies ... have shown that people don't recognize any longer even themselves in facial composites, but they react to those composites in a positive manner. So next time you are looking for a certain product, and there is an ad suggesting you to buy it, it will not be just a standard spokesperson. It will be one of your friends, and you will not even know that this is happening.
>- Alessandro Acquisti (https://www.ted.com/talks/alessandro_acquisti_why_privacy_matters)

#How does your data get out (exfiltration)?

* Speech to text/Dictation
  * Siri
  * Cortana
  * OK Google
  * Alexa
* Networking
* Predictions/Caching
* Search
* Personalization
* Backup
* Location Services
* Error Reporting
* Integrated Content
* App Store
* Cloud Services
  * iCloud
  * OneDrive
* Updates


#Actions (What should I do?)

* Identify Your Data
* Take Ownership
* Participate Actively


#Tools

* Networking/Firewalls
  * pfsense
  * tomato router
  * ddwrt
  * openwrt
  * /etc/hosts
  * \WINDOWS\system32\drivers\etc\etc\hosts

* Windows Software
  * netstat (-a -b -n)
  * Windows 10 Firewall Control
  * GlassWire
  * NetLimiter
  * Outpost Security Suite
  * ZoneAlarm

* Mac OSX Software
  * LittleSnitch - https://www.obdev.at/products/littlesnitch
  * Radio Silence - https://radiosilenceapp.com/
  * Security Growler - https://pirate.github.io/security-growler/
  * nettop (BSD)
  * pfctl (BSD)
    * Icefloor - http://www.hanynet.com/icefloor/
    * Murus - http://www.murusfirewall.com/
  * net-monitor (experimental) -  https://github.com/fix-macosx/net-monitor

#Windows Settings - https://fix10.isleaked.com/

```
reg delete HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo\ /v Id /f
reg delete HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener
reg delete HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo\ /v Enabled /t REG_DWORD /d 0 /f
reg add “HKCU\Control Panel\International\User Profile\ /v HttpAcceptLanguageOptOut” /t REG_DWORD /d 1 /f
reg add HKCU\SOFTWARE\Microsoft\InputPersonalization\ /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg add HKCU\SOFTWARE\Microsoft\InputPersonalization\ /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
reg add HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore\ /v HarvestContacts /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Personalization\Settings\ /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\ /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener\ /v Start /t REG_DWORD /d 0 /f
```

https://gist.github.com/vip3rc0de/a0d2d90f52f9e7c90de0
https://gist.github.com/shrayasr/d3a4987ebd5b508f6490

```
@echo off
cls
set x86="%SYSTEMROOT%\System32\OneDriveSetup.exe"
set x64="%SYSTEMROOT%\SysWOW64\OneDriveSetup.exe"
echo Closing OneDrive process.
echo.
taskkill /f /im OneDrive.exe > NUL 2>&1
ping 127.0.0.1 -n 5 > NUL 2>&1
echo Uninstalling OneDrive.
echo.
if exist %x64% (
%x64% /uninstall
) else (
%x86% /uninstall
)
ping 127.0.0.1 -n 5 > NUL 2>&1
echo Removing OneDrive leftovers.
echo.
rd "%USERPROFILE%\OneDrive" /Q /S > NUL 2>&1
rd "C:\OneDriveTemp" /Q /S > NUL 2>&1
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S > NUL 2>&1
rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S > NUL 2>&1 
echo Removing OneDrive from the Explorer Side Panel.
echo.
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > NUL 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > NUL 2>&1
pause
```

#OSX Settings - https://github.com/drduh

##Daemons/Agents
Type | Location | Run on behalf of
---- | -------- | ----------------
User Agents|~/Library/LaunchAgents|Currently logged in user
Global Agents|/Library/LaunchAgents|Currently logged in user
Global Daemons|/Library/LaunchDaemons|root or the user specified with the key User
System Agents|/System/Library/LaunchAgents|Currently logged in user
System Daemons|/System/Library/LaunchDaemons|root or the user specified with the key User

##How can I see what is running

* Current user
`$ launchctl list`
* root for the current user
`$ sudo launchctl list`



##What is that thing?

defaults read $LOCATION/$PLISTNAME
e.g.
```
$ defaults read /System/Library/LaunchAgents/com.apple.AirPlayUIAgent.plist
$ defaults read /System/Library/LaunchDaemons/com.apple.airplaydiagnostics.server.mac.plist
```


##Helpful hints:

* http://cirrusj.github.io/Yosemite-Stop-Launch/
* Entries for Program/Program Arguments
  * run it
  * man pages
* Google
* Filesystem
* start/stop the service

```
#Type               Location                        Run on behalf of
#User Agents        ~/Library/LaunchAgents          Currently logged in user
#Global Agents      /Library/LaunchAgents           Currently logged in user
#Global Daemons     /Library/LaunchDaemons          root or the user specified with the key User
#System Agents      /System/Library/LaunchAgents    Currently logged in user
#System Daemons     /System/Library/LaunchDaemons   root or the user specified with the key User

# Disable Resume system-wide
defaults write com.apple.systempreferences NSQuitAlwaysKeepsWindows -bool false
defaults write NSGlobalDomain NSQuitAlwaysKeepsWindows -bool false

# Disable the crash reporter
defaults write com.apple.CrashReporter DialogType -string "none"

# Stop Google Chrome from automatically updating
# Run manually - /Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Resources/
defaults write com.google.Keystone.Agent checkInterval 0

# Disable Notification Center and remove the menu bar icon
launchctl unload -w /System/Library/LaunchAgents/com.apple.notificationcenterui.plist 2> /dev/null

# Create a zero-byte file instead of a sleep image
sudo touch /private/var/vm/sleepimage
# make sure it can’t be rewritten
sudo chflags uchg /private/var/vm/sleepimage

# Stop iTunes from responding to the keyboard media keys
launchctl unload -w /System/Library/LaunchAgents/com.apple.rcd.plist 2> /dev/null

# Empty Trash securely by default
defaults write com.apple.finder EmptyTrashSecurely -bool true

# do not ask for new devices to be time machine backups
defaults write com.apple.TimeMachine DoNotOfferNewDisksForBackup -bool true
# disable local time machine backups
hash tmutil &> /dev/null && sudo tmutil disablelocal

#turn on the OSX firewall (alf)
sudo defaults write /Library/Preferences/com.apple.alf globalstate -bool true

#turn on logging for the OSX firewall (alf)
sudo defaults write /Library/Preferences/com.apple.alf loggingenabled -bool true

#enable ICMP ping stealth
sudo defaults write /Library/Preferences/com.apple.alf stealthenabled -bool true

#disable firewall-free operations for "signed" applications
#this may lead to a "noisy" experience until each installed application is configured
sudo defaults write /Library/Preferences/com.apple.alf allowsignedenabled -bool false

#disable captive portal handling service -- use a browser instead
sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.captive.control Active -bool false

#disable Apple Push Notification Service daemon
#https://apple.stackexchange.com/questions/92214/how-to-disable-apple-push-notification-service-apsd-on-os-x-10-8
#re-enable with sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.apsd.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.apsd.plist

#some kind of game controller, possible interaction with appleTV?
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.GameController.gamecontrollerd.plist

#DNS services - safer without this, but DNS really doesn't work without it (problems anyone?)
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder*
#sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
#sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponderHelper.plist

#This is the launchd configuration file for DumpPanic, an application that dumps kernel panic information from NVRAM and saves it. If "Diagnostics & Usage" (under "Privacy") in the Settings app is set to "Automatically Send", the information is eventually submitted to Apple. 
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.DumpPanic.plist

#disable reporting crash data to Apple
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.CrashReporterSupportHelper.plist

#Part of the CoreRAID private framework
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.CoreRAID.plist

# Disable ichat
launchctl unload -w /System/Library/LaunchAgents/com.apple.soagent.plist

#disable Calendar agent services
launchctl unload -w /System/Library/LaunchAgents/com.apple.CalendarAgent.plist

#disable social push for facebook, linkedin, tencentweibo, twitter, and weibo
launchctl unload -w /System/Library/LaunchAgents/com.apple.SocialPushAgent.plist

# sharingd -- Sharing Daemon that enables AirDrop, Shared Computers, and Remote Disc in the Finder.
launchctl unload -w /System/Library/LaunchAgents/com.apple.sharingd.plist
# this can be re-enabled on demand vvv
#launchctl load -w /System/Library/LaunchAgents/com.apple.sharingd.plist

#app store linked game center notification push services
launchctl unload -w /System/Library/LaunchAgents/com.apple.gamed.plist

#disable AirPlay
launchctl unload -w /System/Library/LaunchAgents/com.apple.AirPlayUIAgent.plist

#disable appleseed (part of the Feedback Assistant)
launchctl unload -w /System/Library/LaunchAgents/com.apple.appleseed.seedusaged.plist

#safari/embedded plugin support
launchctl unload -w /System/Library/LaunchAgents/com.apple.WebKit.PluginAgent.plist

#related to scoped bookmarks.  some reports of keychain agent effects with this one
launchctl unload -w /System/Library/LaunchAgents/com.apple.scopedbookmarkagent.xpc.plist

#disable dictation and speech STT
launchctl unload -w  /System/Library/LaunchAgents/com.apple.assistant*
#disables the following:
#launchctl unload -w  /System/Library/LaunchAgents/com.apple.assistantd.plist
#launchctl unload -w  /System/Library/LaunchAgents/com.apple.assistant_service.plist

#disable agent to handle AirPort Base Station and Time Capsule (not advised if you use these things)
launchctl unload -w  /System/Library/LaunchAgents/com.apple.AirPortBaseStationAgent.plist

#iCloud notification related service
launchctl unload -w /System/Library/LaunchAgents/com.apple.AOSPushRelay.plist

#icloud
launchctl unload -w /System/Library/LaunchAgents/com.apple.icloud*

# Disable Notification Center
# https://apple.stackexchange.com/questions/106149/how-do-i-permanently-disable-notification-center-in-mavericks
launchctl unload -w /System/Library/LaunchAgents/com.apple.notificationcenterui.plist

#disable pushing history to the cloud
launchctl unload -w /System/Library/LaunchAgents/com.apple.SafariCloudhistoryPushAgent.plist

#disable address book services
launchctl unload -w /System/Library/LaunchAgents/com.apple.AddressBook*

#rcd routes media transport key and remote controller commands to the appropriate applications
launchctl unload -w /System/Library/LaunchAgents/com.apple.rcd.plist

#family control services
launchctl unload -w /System/Library/LaunchAgents/com.apple.family*

#parental controls
launchctl unload -w /System/Library/LaunchAgents/com.apple.parentalcontrols.check.plist

#accessibility screen reader
launchctl unload -w /System/Library/LaunchAgents/com.apple.ScreenReaderUIServer.plist

#talagent is the helper agent for the Transparent App Lifecycle feature. (talagent can be run manually/independent of daemon usage)
launchctl unload -w /System/Library/LaunchAgents/com.apple.talagent.plist

#disable bluetooth audio
launchctl unload -w /System/Library/LaunchAgents/com.apple.bluetoothAudioAgent.plist

#disable all bluetooth (do not expect bluetooth to work)
launchctl unload -w /System/Library/LaunchAgents/com.apple.bluetoothUIServer.plist

#agent for Core MIDI services
launchctl unload -w /System/Library/LaunchAgents/com.apple.midiserver.plist

#spotlight metadata writing utility (maybe this stops .DS_Store?)
launchctl unload -w /System/Library/LaunchAgents/com.apple.metadata.mdwrite.plist

#spindump is used by various system components to create reports when an unresponsive application is force quit.i
#Reports are stored at: /Library/Logs/DiagnosticReports/
#For normal application force quits spindump will display a dialog to offer the choice to view more details and/or send a report to Apple.
launchctl unload -w /System/Library/LaunchAgents/com.apple.spindump_agent.plist

#VoiceOver.app for accessibility
launchctl unload -w /System/Library/LaunchAgents/com.apple.VoiceOver.plist

#sync for some uid and server
launchctl unload -w /System/Library/LaunchAgents/com.apple.syncservices.*
#launchctl unload -w /System/Library/LaunchAgents/com.apple.syncservices.uihandler.plist
#launchctl unload -w /System/Library/LaunchAgents/com.apple.syncservices.SyncServer.plist

#disable speech services
launchctl unload -w /System/Library/LaunchAgents/com.apple.speech.*
#launchctl unload -w /System/Library/LaunchAgents/com.apple.speech.voiceinstallerd.plist
#launchctl unload -w /System/Library/LaunchAgents/com.apple.speech.synthesisserver.plist
#launchctl unload -w /System/Library/LaunchAgents/com.apple.speech.recognitionserver.plist
#launchctl unload -w /System/Library/LaunchAgents/com.apple.speech.feedbackservicesserver.plist
#launchctl unload -w /System/Library/LaunchAgents/com.apple.speech.speechdatainstallerd.plist

#app store related agent
launchctl unload -w /System/Library/LaunchAgents/com.apple.maspushagent.plist

#pushes hardware and OSX details to apple
launchctl unload -w /System/Library/LaunchAgents/com.apple.Maps.pushdaemon.plist

#disable screensharing
launchctl unload -w /System/Library/LaunchAgents/com.apple.screensharing.*
#launchctl unload -w /System/Library/LaunchAgents/com.apple.screensharing.agent.plist
#launchctl unload -w /System/Library/LaunchAgents/com.apple.screensharing.MessagesAgent.plist

#disable remote desktop
launchctl unload -w /System/Library/LaunchAgents/com.apple.RemoteDesktop.plist

#disables printing! -- be careful
launchctl unload -w /System/Library/LaunchAgents/com.apple.print*
#launchctl unload -w /System/Library/LaunchAgents/com.apple.printuitool.agent.plist
#launchctl unload -w /System/Library/LaunchAgents/com.apple.printtool.agent.plist

#Used internally for communication with Mobile Device Management (Profile Manager) server
#Part of Managed Client (MCX)
launchctl unload -w /System/Library/LaunchAgents/com.apple.mdmclient.agent.plist

#FindMyMac.app location agent
#https://www.stigviewer.com/stig/apple_os_x_10.9_mavericks_workstation/2015-02-26/finding/V-58353
launchctl unload -w /System/Library/LaunchAgents/com.apple.findmymacmessenger.plist

#iCloud photos sync?
launchctl unload -w /System/Library/LaunchAgents/com.apple.photolibraryd.plist

# Disable NetBIOS daemon (netbiosd)
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.netbiosd.plist
# Disable Location Services (locationd)
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.locationd.plist

# Disable QuickLook
# https://superuser.com/questions/617658/quicklooksatellite-mac-os-high-cpu-use
launchctl unload -w /System/Library/LaunchAgents/com.apple.quicklook.*

# Disable Spotlight
# http://osxdaily.com/2011/12/10/disable-or-enable-spotlight-in-mac-os-x-lion/
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.metadata.mds.plist

#must disable SIP first
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.AirPlayXPCHelper.plist
#Do I need kerberos?
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.Kerberos.*
#IMAgents for facetime
launchctl unload -w /System/Library/LaunchAgents/com.apple.ima*
launchctl unload -w /System/Library/LaunchAgents/com.apple.java*

###UNTESTED###
#ifcstart -- rebuilds international data caches
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.IFCStart.plist
```
