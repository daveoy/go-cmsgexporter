cd /root/go-cmsgexporter
export http_proxy=$1
export https_proxy=$1
GIT_SSL_NO_VERIFY=true git pull
systemctl restart cmsg_exporter
