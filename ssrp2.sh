docker run -p 8002:80 \
	-d \
        --name ssrp2 \
        -v $PWD/ldap.conf:/etc/ldap/ldap.conf \
        -v $PWD/hosts:/etc/hosts \
        -v $PWD/cs401-DC-CA.cer:/etc/ssl/certs/cs401-DC-CA.cer \
        -v $PWD/ssp.conf.php:/var/www/conf/config.inc.local.php \
        -v $PWD/config.inc.php:/var/www/conf/config.inc.php \
    -it docker.io/ltbproject/self-service-password:latest