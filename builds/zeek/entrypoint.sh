#!/bin/bash

rm -f /zeek-spool/*.log

/usr/local/zeek/bin/zeek -j -C local cluster-supervisor json-streaming-logs

