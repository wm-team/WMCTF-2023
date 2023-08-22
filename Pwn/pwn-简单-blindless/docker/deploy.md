```bash
sudo docker run -tid -e FLAG="flag{ad0c56ac-7710-4bca-ad83-08e8c9b66ebb}" -p "0.0.0.0:9999:9999" --name="blendless" cnitlrt/wmctf:blindless
```

> -e FLAG="flag{ad0c56ac-7710-4bca-ad83-08e8c9b66ebb}"中的`flag{ad0c56ac-7710-4bca-ad83-08e8c9b66ebb}`是flag值。
>
> 0.0.0.0:9999:9999中的第一个9999是要映射端口，第二个9999是内部端口
>
> --name="blendless"是运行时候容器的名称