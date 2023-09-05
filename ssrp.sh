docker rm -f ssrp
docker build -t salehhajiyev/ssrp .
docker run -p 8001:80 \
        -d \
        --name ssrp \
        -v $PWD/hosts:/etc/hosts \
        -v $PWD/ssp.conf.php:/var/www/conf/config.inc.local.php \
        -v $PWD/config.inc.php:/var/www/conf/config.inc.php \
        salehhajiyev/ssrp
docker image prune -af