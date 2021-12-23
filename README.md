<p align="center">
  <a href="https://fishy-project.eu" target="_blank"><img width=200 src="https://i.imgur.com/K06KiZV.png" alt="FISHY website"></a>
  <h2 align="center">FISHY Network Behavioral Analysis</h2>
</p>


## Introduction
In this document we provide a simple and brief description of the FISHY behavioral analysis component proposed architecture and it's basic required installation/integration steps.

## Fundamentals

### Zeek
[Zeek](https://zeek.org) is powerful, free and open-source network analysis framework that is much different from your typical IDS. One of the main benefits of Zeek is it's extensive set of logs describing network activity. In addition to the logs, Zeek comes with multiple built-in functionalities for a range of analysis and detection tasks. In addition to shipping such powerful functionality “out of the box,” Zeek is a fully customizable and extensible platform for traffic analysis. Zeek provides users a domain-specific, Turing-complete scripting language for expressing arbitrary analysis tasks. Zeek's simple architeture can be modelled as below:
<p align="center">
  <img width=200 src="https://i.imgur.com/l2fFc0Q.png">
</p>

We will use Zeek both to generate and report netowork behavioural metrics(ex. SYN packets/s) and also load some predefined scripts to detected and report certain anomalies  (ex. [SSH Brutefocing](https://github.com/zeek/zeek/blob/master/scripts/policy/protocols/ssh/detect-bruteforcing.zeek)).

### Filebeat
[Filebeat](https://www.elastic.co/beats/filebeat) is a free and open-source lightweight log shipper that belongs to the [beats](https://github.com/elastic/beats) family. We will setup filebeat so it can ingest the logs generated by Zeek and send them to Logstash.
> **Note**: Filebeat has a native Zeek [input module](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-zeek.html) that parses Zeek generated json logs to the ECS(Elastic Common Schema) format which will not be used in this component (for now).

### Logstash
[Logstash](https://www.elastic.co/logstash) is a free and open-source lightweight data processing pipeline that allows you to collect data from a variety of sources, parse it, transform it and send it to your desired destination. We will use Logstash to intake log & metric data from Filebeat, parse it as json, do some data transformation and forward it to a RabbitMQ exchange with a specific exchange key based on the log & metric type. 
> **Note**: Logtash has a native RabbitMQ [output integration plugin](https://www.elastic.co/guide/en/logstash/current/plugins-outputs-rabbitmq.html).

## Installation

### Docker
Make sure you have both docker and docker-compose and that docker.service is running. 

#### Ubuntu
```sh
$ sudo apt install docker.io docker-compose
$ sudo systemctl enable --now docker
```
#### Arch
```sh
$ sudo pacman -S docker docker-compose
$ sudo systemctl enable --now docker
```
### Clone the repo

```sh
$ git clone https://github.com/nonvegan/FISHY-NetAnalysis.git
```
### Configure Zeek
Please configure zeek in the [zeek entrypoint script](builds/zeek/script.sh) to listen on your desired interface, you can use the ```-i <interface>``` flag. You can also load additional scripts, using the ones in the [Zeek's policy folder](https://github.com/zeek/zeek/tree/master/scripts/policy) or copying new ones to the [scripts folder](builds/zeek/scripts) and appending their name to the entrypoint command.

### Start the docker containers
```sh
$ cd FISHY-NetAnalysis
$ docker-compose build
$ docker-compose up
```
You can check the status of the containers using 
```sh
$ docker ps
```

### Configure RabbitMQ
By default logstash will set the message routing key according to the log filename, for example, logs messages from the file ```conn.log``` will have it's routing key set to ```zeek.conn```. Please make sure you have created the queues and exchange key bindings for the desired log files, you can check Zeek's available logs [here](https://docs.zeek.org/en/master/script-reference/log-files.html).
> **Note**: This process will be automated in the future
>
> **Note**: By default, logstash will send the messages to the ```amq.direct``` exchange.

For testing purposes this docker-compose build includes a rabbitmq instance, if you wish to use your own rabbitMQ instance please delete the service entry from the [docker-compose.yml file](docker-compose.yml) and configure the [logstash config file](builds/logstash/logstash.conf) with your own credentials. 

You can access the RabbitMQ management page at ```http://localhost:15672``` with the username ```admin``` and password ```pleasechangeme```.





