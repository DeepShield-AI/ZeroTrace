# ZeroTrace STANDALONE mode docker-compose deployment package

## Usage

```console
unset DOCKER_HOST_IP
DOCKER_HOST_IP="10.1.2.3"  # FIXME: Deploy the environment machine IP
wget  https://zerotrace-ce.oss-cn-beijing.aliyuncs.com/pkg/docker-compose/stable/linux/zerotrace-docker-compose.tar
tar -zxf zerotrace-docker-compose.tar 
sed -i "s|FIX_ME_ALLINONE_HOST_IP|$DOCKER_HOST_IP|g" zerotrace-docker-compose/docker-compose.yaml
docker-compose -f zerotrace-docker-compose/docker-compose.yaml up -d
```

## License

[Apache 2.0 License](../../LICENSE).