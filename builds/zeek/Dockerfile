FROM zeekurity/zeek:lts

WORKDIR /zeek-spool

COPY script.sh /script.sh

COPY scripts/*.zeek /usr/local/zeek/share/zeek/site/

ENTRYPOINT ["/bin/bash"]

CMD ["/script.sh"]

