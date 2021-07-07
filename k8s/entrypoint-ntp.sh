#!/bin/sh
if [ -z "${NTP_CONF_FILE}" ]
then
    NTP_CONF_FILE="/etc/ntpd.conf"
fi
ntpd -v -d -s -f ${NTP_CONF_FILE}
