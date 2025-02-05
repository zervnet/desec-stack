#!/bin/bash

# list of domains we're using
DOMAINS="\
    checkipv4.dedyn.${DESECSTACK_DOMAIN} \
    checkipv6.dedyn.${DESECSTACK_DOMAIN} \
    checkip.dedyn.${DESECSTACK_DOMAIN} \
    dedyn.${DESECSTACK_DOMAIN} \
    desec.${DESECSTACK_DOMAIN} \
    update6.dedyn.${DESECSTACK_DOMAIN} \
    update.dedyn.${DESECSTACK_DOMAIN} \
    www.dedyn.${DESECSTACK_DOMAIN} \
    get.desec.${DESECSTACK_DOMAIN} \
    www.desec.${DESECSTACK_DOMAIN}"

# list of files we expect at /etc/ssl/private/
FILES_NEEDED=$(for DOMAIN in $DOMAINS ; do echo $DOMAIN.cer ; echo $DOMAIN.key ; done | sort)
FILES_PRESENT=$(cd /etc/ssl/private && ls -1 | sort)
FILES_MISSING=$(diff <(echo "$FILES_NEEDED" ) <(echo "$FILES_PRESENT") | egrep '^-.*(cer|key)' | cut -b 2-)

# link certs
if [ ! -z "$FILES_MISSING" ] ; then

    # generate certificates
    mkdir -p /autocert/
    (
        cd /autocert/
        echo "Autogenerating certificates for www in " $(pwd)

        for DOMAIN in $DOMAINS; do

            echo "Autogenerating certificate for $DOMAIN ..."
            openssl req \
                -newkey rsa:2048 \
                -nodes \
                -keyout $DOMAIN.key \
                -x509 \
                -days 1\
                -out $DOMAIN.cer \
                -subj "/C=DE/ST=Berlin/L=Berlin/O=deSEC/OU=autocert/CN=$DOMAIN"

        done

        echo "Autogeneration completed. Your certificates in " $(pwd) ":"
        ls -1
    )

    # inform the user
    echo "############################################################"
    echo "WARNING some certificate or key files are missing, falling"
    echo "        back to auto-generated self-signed certificates"
    echo "############################################################"
    echo "####### your files in $DESECSTACK_WWW_CERTS:"
    ls -1 /etc/ssl/private/
    echo "############################################################"
    echo "####### missing in $DESECSTACK_WWW_CERTS:"
    for FILE in $FILES_MISSING ; do
        echo $FILE
    done
    echo "############################################################"

    # setup certificate path
    export CERT_PATH=/autocert/
else
    # inform the user
    echo "Found all certificates, using user-provided certificates."

    # setup certificate path
    export CERT_PATH=/etc/ssl/private/
fi

# replace environment references in config files
/etc/nginx/sites-available/envreplace.sh

(
  echo "Starting nginx"
  nginx -g 'daemon off;' && exit 1
) &

nginx_pid=$!
echo "nginx PID: ${nginx_pid}"

if [ -z "$FILES_MISSING" ] ; then
  (
    echo "Setting up monitoring for certificate files in $CERT_PATH"
    inotifywait -m -e create,modify,move,delete $CERT_PATH | while read line; do
      echo "File update detected: $line"

      nginx -t
      if [ $? -ne 0 ]; then
        echo "Error: invalid nginx configuration"
      else
        echo "Reloading nginx with new configuration"
        nginx -s reload
      fi
    done

    echo "inotifywait failed, killing nginx with PID ${nginx_pid}"
    kill -TERM $nginx_pid
  ) &
else
  echo "Warning: Not monitoring certificate rotation as not all certificates were provided"
fi

wait $nginx_pid || exit 1
