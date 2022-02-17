# A wireshark lua plugin for IPsec in TCP (RFC8229)

This is a wireshark plugin to decode IKE/ESP packet encapsulated in TCP according to RFC8229;

## Installation
Copy the wireshark_ipsectcp_plugin.lua file into wireshare lua plugin folder, then either restart wireshark or ctrl+shift+L to load the plugin.

By default,this plugin will decode any TCP packet has either src or dst port == 4500; for other TCP port, you could use wireshare "Decode As..." menu
