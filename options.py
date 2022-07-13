# Device to use for capturing (Must support monitor mode)
device = 'wlan0'

# Time (in seconds) to retrieve the AP list in the Session Create page
time_get_ap_list = 5

# Time (in seconds) to retrieve the clients list in the Session Modify page
time_get_clients_list = 10

# Number of deauthentication packets being sent to the client during the handshake process in Session Modify page
handshake_no_deauth_packets = 5

# Time (in seconds) to retry the handshake process when it fails to capture EAPOL in Session Modify page
time_handshake_retry = 10
