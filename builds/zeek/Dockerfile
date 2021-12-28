FROM zeekurity/zeek:lts

WORKDIR /zeek-spool

COPY entrypoint.sh /entrypoint.sh

COPY scripts/*.zeek /usr/local/zeek/share/zeek/site/

ENTRYPOINT ["/bin/bash"]

CMD ["/entrypoint.sh"]

