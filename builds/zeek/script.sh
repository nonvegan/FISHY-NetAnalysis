#!/bin/bash
echo Starting Zeek!
rm -f /zeek-spool/*.log
/usr/local/zeek/bin/zeek -C -i eth0 local json-streaming-logs

