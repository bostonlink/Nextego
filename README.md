# README - Nextego v1.0

Author: J. David Bressler (@bostonlink)<br />
Demo Video: Pending release of Nextego

## 1.0 About

Nextego is a local maltego transform pack built with the Canari Framework that integrates Rapid7's Nexpose vulnerability scanner and Maltego.  Nextego is able to launch vulnerability scans right from a Maltego graph as well as output open ports, services, service version/fingerprint, vulnerabilities, available metasploit modules, and available exploit-db exploits associated with a vulnerability.

Directory Structure:

* `src/nextego` directory is where all the magic stuff goes and happens.
* `src/nextego/transforms` directory is where all the transform modules are located.
* `src/nextego/transforms/common` directory is where common code for all transforms are stored.
* `src/nextego/transforms/common/entities.py` is where custom entities are defined.
* `maltego/` is where the Maltego entity exports are stored.
* `src/nextego/resources/maltego` directory is where the `entities.mtz` and `*.machine` files are stored for auto install and uninstall.

## 2.0 - Installation

### 2.1 - Supported Platforms
nextego has currently been tested on Mac OS X and Linux.

### 2.2 - Requirements
nextego is supported and tested on Python 2.7.3

The canari framework must be installed to use this package
See: https://github.com/allfro/canari

### 2.3 - How to install
Once you have the Canari framework installed and working, follow the directions below to install cuckooforcanari

Install the package:

```bash
$ git clone git@github.com:bostonlink/Nextego.git
$ cd nextego
$ python setup.py install
```
Then install the nextego package by issuing the following command:

```bash
$ canari install-package nextego
```
Once installed you must edit the nextego.conf configuration file.

```bash
$ vim ~/.canari/nextego.conf
```
All Done!!  Happy Hunting!