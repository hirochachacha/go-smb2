FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        netcat-openbsd \
        samba \
        samba-ad-dc \
        smbclient \
        winbind \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/smb-test-server

EXPOSE 88/tcp 88/udp 445/tcp

HEALTHCHECK --interval=2s --timeout=5s --start-period=10s --retries=45 \
    CMD nc -z 127.0.0.1 88 \
        && smbclient -L //127.0.0.1 \
            -U 'SMB2TEST/smbuser%Smbpasswd12345' >/dev/null

ENTRYPOINT ["/usr/local/bin/smb-test-server"]
