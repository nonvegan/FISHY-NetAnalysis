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

We will use Zeek both to generate and report network behavioural metrics(ex. SYN packets/s) and also load some predefined scripts to detected and report certain anomalies (ex. [SSH Brutefocing](https://github.com/zeek/zeek/blob/master/scripts/policy/protocols/ssh/detect-bruteforcing.zeek)).

### Fluentd
Fluentd is an open source log shipper, which lets you unify the data collection and consumption. We will use Fluentd to watch logs produced by Zeek and ship them to specific RabbitMQ queues.

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

### Kubernetes
Make sure you have both minikube & kubectl installed and that libvirtd.service is running.

#### Ubuntu
```sh
$ curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube_latest_amd64.deb
$ sudo dpkg -i minikube_latest_amd64.deb
$ curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
$ sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```
#### Arch
```sh
$ sudo pacman -S minikube kubectl
$ usermod -aG libvirt $(whoami)
$ sudo systemctl enable --now libvirtd
$ minikube config set driver kvm2
```

### Clone the repo

```sh
$ git clone https://github.com/nonvegan/FISHY-NetAnalysis.git
```
### Configure Zeek
Please configure zeek in the [zeek entrypoint script](builds/zeek/script.sh) to listen on your desired interface, you can use the ```-i <interface>``` flag. You can also load additional scripts, using the ones in the [Zeek's policy folder](https://github.com/zeek/zeek/tree/master/scripts/policy) or copying new ones to the [scripts folder](builds/zeek/scripts) and appending their name to the entrypoint command.

### Start the Kubernetes cluster
```sh
$ cd FISHY-NetAnalysis
$ minikube start
$ kubectl apply -f rabbitmq.yml
```
You can check the status of the cluster using:
```sh
$ kubectl get svc
```
> **Note**: You can find the ip of minikube using ```minikube ip```

### Start the docker containers
```sh
$ docker-compose build
$ docker-compose up
```
You can check the status of the containers using 
```sh
$ docker ps
```

### Configure RabbitMQ
By default fluentd will set the message routing key according to the log filename, for example, logs messages from the file ```conn.log``` will have it's routing key set to ```zeek.conn```. Please make sure you have created the queues and exchange key bindings for the desired log files, you can check Zeek's available logs [here](https://docs.zeek.org/en/master/script-reference/log-files.html).
> **Note**: This process will be automated in the future
>
> **Note**: By default, fluentd will send the messages to the ```amq.direct``` exchange.

For testing purposes this docker-compose build includes a rabbitmq instance, if you wish to use your own rabbitMQ instance please delete the service entry from the [docker-compose.yml file](docker-compose.yml) and configure the [logstash config file](builds/logstash/logstash.conf) with your own credentials. 

You can access the RabbitMQ management page at ```http://localhost:15672``` with the username ```admin``` and password ```pleasechangeme```.





