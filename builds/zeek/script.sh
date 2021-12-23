#!/bin/bash
echo Starting Zeek!
rm -f /zeek-spool/*.log
/usr/local/zeek/bin/zeek -C -i wlp2s0 local json-streaming-logs

