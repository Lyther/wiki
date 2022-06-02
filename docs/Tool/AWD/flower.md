# flower

TCP flow analyzer with sugar for Attack/Defense CTF

## What is it?

[![demo_image](https://news.topnotch.works/host-https-github.com/secgroup/flower/raw/master/demo_images/demo3.png?raw=true)](https://news.topnotch.works/host-https-github.com/secgroup/flower/blob/master/demo_images/demo3.png?raw=true)

Flower is an automatic packet analyzer made by Ca' Foscari University team for the CyberChallenge attack/defense CTF held in Rome on June 27th, 2018.

This tool was written in less than ten days, but it works! Every **contribution** is welcome!

Presentation of Flower (from min 7:30), and general introduction to CTFs at ESC2K18 in Italian:

[![tools presentation](https://news.topnotch.works/host-https-camo.githubusercontent.com/dc02654464d41ab953dd03ea5d8dcbc405c0b58e0ac7aa730d208b351a2e9a0b/687474703a2f2f696d672e796f75747562652e636f6d2f76692f6f4742374c4677546768452f302e6a7067)](https://news.topnotch.works/host-http-www.youtube.com/watch?v=oGB7LFwTghE)

## Features

- Only one command needed to have it up, thanks to docker.
- Flow list
- **Vim like navigation** ( `k` and `j` to navigate the list)
- Regex filtering with highlight [![img](https://news.topnotch.works/host-https-github.com/secgroup/flower/raw/master/demo_images/demo_search_hilight.png?raw=true)](https://news.topnotch.works/host-https-github.com/secgroup/flower/blob/master/demo_images/demo_search_hilight.png?raw=true)
- Highlight in red flow with flags
- Favorite management
- Time filter
- Service filter [![img](https://news.topnotch.works/host-https-github.com/secgroup/flower/raw/master/demo_images/demo_service_selection.png)](https://news.topnotch.works/host-https-github.com/secgroup/flower/blob/master/demo_images/demo_service_selection.png)
- Colored hex dump [![img](https://news.topnotch.works/host-https-github.com/secgroup/flower/raw/master/demo_images/demo_hex_dump.png?raw=true)](https://news.topnotch.works/host-https-github.com/secgroup/flower/blob/master/demo_images/demo_hex_dump.png?raw=true)
- Automatic export GET/POST requests directly in python-format [![img](https://news.topnotch.works/host-https-github.com/secgroup/flower/raw/master/demo_images/demo_request_export.png)](https://news.topnotch.works/host-https-github.com/secgroup/flower/blob/master/demo_images/demo_request_export.png)
- Automatic export to pwntools [![img](https://news.topnotch.works/host-https-github.com/secgroup/flower/raw/master/demo_images/demp_export_pwn.png)](https://news.topnotch.works/host-https-github.com/secgroup/flower/blob/master/demo_images/demp_export_pwn.png)

## Getting Started

### Run with docker

Clone the repo, enter in the directory, and just run `docker-compose up`, and after a while, you will find flower at [http://localhost:3000](https://news.topnotch.works/host-http-localhost:3000).

For the flag regex, modify `REACT_APP_FLAG_REGEX` in `docker-compose.yml`.

The build will automatically import the test pcaps.

To enter in the service to import other pcaps, run `docker exec -it flower_flower-python_1 /bin/bash` (if the flower is in a folder with a different name, modify the prefix after `-it`). The container shares the `/shared` folder with the host. Put the pcap files inside this folder and use `python services/importer.py /shared/pcap_file_here` from the container to import pcaps to flower.

### Manual installation

1. Clone and install dependencies

   ```
   git clone https://github.com/secgroup/flower
   cd flower
   npm install 
   pip install -r services/requirements.txt
   ```

2. (Optional) Set the following environment variables:

- `REACT_APP_FLOWER_MONGO` IP of the host that will have flower db active (MongoDB)
- `REACT_APP_FLOWER_SERVICES` IP of the host that will have services active
- `REACT_APP_FLAG_REGEX` regex that matches flags.

1. Mongodb is required on the same machine that run the services. To start it: `sudo mongod --dbpath /path/to/mongodb/db --bind_ip 0.0.0.0`

#### Run

1. Start flower

   ```
   ./run.sh
   ```

2. Start flower services

   ```
   cd services
   ./run_ws.sh
   ```

Once everything has been started, the flower should be accessible at the address of the machine that started it on port 3000.

### Pcap import

You must first install pynids from [here](https://news.topnotch.works/host-https-github.com/MITRECND/pynids). The pip version is outdated! Good luck with the installation. Then, you can import pcaps into MongoDB by executing the provided script `importer.py` as follows:

```
cd services
./importer.py pcap_file.pcap
```

You can find a test_pcap in `services/test_pcap`. For a quick demo, run `./importer.py test_pcap/dump-2018-06-27_13:25:31.pcap`

## Security tips (Important!)

If you are going to use the flower in a CTF, remember to set up the firewall in the most appropriate way, as the current implementation does not use other security techniques.

> If you ignore this, everybody will be able to connect to your database and steal all your flags!

## Link

Github repo: https://news.topnotch.works/host-https-github.com/secgroup/flower