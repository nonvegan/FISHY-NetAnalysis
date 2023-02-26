<p align="center">
  <a href="https://fishy-project.eu" target="_blank"><img width=200 src="https://i.imgur.com/K06KiZV.png" alt="FISHY website"></a>
  <h2 align="center">FISHY Network Behavioral Analysis</h2>
</p>


## Introduction
In this document we provide a simple and brief description of Zeek...

## Fundamentals

### Zeek
[Zeek](https://zeek.org) is powerful, free and open-source network analysis framework that is much different from your typical IDS. One of the main benefits of Zeek is it's extensive set of logs describing network activity. In addition to the logs, Zeek comes with multiple built-in functionalities for a range of analysis and detection tasks. In addition to shipping such powerful functionality “out of the box,” Zeek is a fully customizable and extensible platform for traffic analysis. Zeek provides users a domain-specific, Turing-complete scripting language for expressing arbitrary analysis tasks. Zeek's simple architeture can be modelled as below:
<p align="center">
  <img width=200 src="https://i.imgur.com/l2fFc0Q.png">
</p>

We will use Zeek both to generate and report network behavioural metrics(ex. SYN packets/s) and also load some predefined scripts to detected and report certain anomalies (ex. [SSH Brutefocing](https://github.com/zeek/zeek/blob/master/scripts/policy/protocols/ssh/detect-bruteforcing.zeek)).
