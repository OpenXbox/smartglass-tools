====================
Wireshark dissectors
====================


===================== ================================== ============================
Variable name                  Mac OSX value                 Windows value
--------------------- ---------------------------------- ----------------------------
GLOBAL_CONFIG_DIR      /usr/share/Wireshark               %WIRESHARK%
GLOBAL_PLUGINS_DIR     /usr/lib/wireshark/plugins/1.7.1   %WIRESHARK%\\plugins\\1.7.1
PERSONAL_CONFIG_DIR    $HOME/.wireshark                   %APPDATA%\\Wireshark
PERSONAL_PLUGINS_DIR   $HOME/.wireshark/plugins           %APPDATA%\\Wireshark\\plugins
===================== ================================== ============================

Usage
-----

The SmartGlass protocol (UDP port 5050) gets dissected automatically.
For Nano, the individual TCP and UDP stream needs to be selected.

1. Mark a packet of the new UDP and TCP stream that appears right after the JSON messaging of SmartGlass
2. Right-click the packet
3. Choose **Decode As**
4. Navigate to **NANO-RDP** in the dropdown list
5. Confirm, Save

Install by referencing paths to lua dissector files
---------------------------------------------------

NOTE: For **PERSONAL_CONFIG_DIR** you have to create that file first

1. Open up *CONFIG_DIR*/init.lua
2. Add the following **AT THE END** of the file

::

  local SG_SCRIPT_PATH = "C:\\Users\\username\\misc_repo\\wireshark\\"
  dofile(SG_SCRIPT_PATH.."smartglass.lua")
  dofile(SG_SCRIPT_PATH.."nano.lua")


Install by moving lua dissector files
-------------------------------------

1. Go to *PLUGINS_DIR*
2. Create a new folder (f.e. '*smartglass*')
3. Move **smartglass.lua** and **nano.lua** to that new folder
