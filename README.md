# PlanB: a distributed HTTP and websocket proxy

[![Build Status](https://travis-ci.org/tsuru/planb.svg?branch=master)](https://travis-ci.org/tsuru/planb)

## What Is It?

PlanB is a HTTP and websocket proxy backed by Redis and inspired by
[Hipache](https://github.com/hipache/hipache).

It aims to be fully compatible with Hipache when Redis is used as a backend.
The same format is used for all keys stored in Redis so migrating from Hipache
to PlanB should be completely seamless. The process should be as simple as
replacing Hipache's executable for PlanB.

## Start-up flags

The following flags are available for configuring PlanB on start-up:

- ``--listen/-l``: the address to which PlanB will bind. Default value is
  ``0.0.0.0:8989``, if you want to disable http access use `disable`.
- ``tls-listen``: the address to which PlanB will bind with tls support.
- ``load-certificates-from``: Path where certificate will found. If value equals 'redis' certificate will be loaded from redis service. Default value is ``redis``
- ``--read-redis-host``: Redis host of the server which contains application
  addresses. Default value is ``localhost``.
- ``--read-redis-port``: Redis port of the server which contains application
  addresses. Default value is ``6379``.
- ``--write-redis-host``: Redis host of the server which PlanB will use for
  publishing dead backends. Default value is ``localhost``.
- ``--write-redis-port``: Redis port of the server which which PlanB will use
  for publishing dead backends. Default value is ``6379``.
- ``--access-log``: File path where access log will be written. If value equals
  ``syslog`` log will be sent to local syslog. If value equals ``stdout`` log will
  be sent to stdout. Default value is ``./access.log``.
- ``--request-timeout``: Total backend request timeout in seconds. Default
  value is ``30``.
- ``--dial-timeout``: Dial backend request timeout in seconds. Default value is
  ``10``.
- ``--dead-backend-time``: Time in seconds a backend will remain disabled after
  a network failure. Default value is ``30``.
- ``--flush-interval``: Time in milliseconds to flush the proxied request.
  Default value is ``10``.
- ``--request-id-header``: Enables PlanB to set a header with an unique ID to
  the requests, facilitating the process of tracing requests.

## Features

* Load-Balancing
* Dead Backend Detection
* Dynamic Configuration
* WebSocket
* TLS

## Install

The easiest way to install PlanB is to pull the trusted build from the hub.docker.com and launch it in the container:

```
# run Redis
docker run -d -p 6379:6379 redis

# run PlanB
docker run -d --net=host tsuru/planb:v1 --listen ":80"
```

## VHOST Configuration

The configuration is managed by **Redis** that makes possible
to update the configuration dynamically and gracefully while
the server is running, and have that state shared across workers
and even across instances.

Let's take an example to proxify requests to 2 backends for the hostname
`www.tsuru.io`. The 2 backends IP are `192.168.0.42` and `192.168.0.43` and
they serve the HTTP traffic on the port `80`.

`redis-cli` is the standard client tool to talk to Redis from the terminal.

Follow these steps:

### Create the frontend:

```
$ redis-cli rpush frontend:www.tsuru.io mywebsite
(integer) 1
```

The frontend identifer is `mywebsite`, it could be anything.

### Add the 2 backends:

```
$ redis-cli rpush frontend:www.tsuru.io http://192.168.0.42:80
(integer) 2
$ redis-cli rpush frontend:www.tsuru.io http://192.168.0.43:80
(integer) 3
```

### Review the configuration:

```
$ redis-cli lrange frontend:www.tsuru.io 0 -1
1) "mywebsite"
2) "http://192.168.0.42:80"
3) "http://192.168.0.43:80"
```

### TLS Configuration using redis (optional)

```
$ redis-cli -x hmset tls:www.tsuru.io certificate < server.crt
$ redis-cli -x hmset tls:www.tsuru.io key < server.key
```

### TLS Configuration using FS (optional)

create directory with this structure
```
cd certficates
ls
*.domain-wildcard.com.key
*.domain-wildcard.com.crt
absolute-domain.key
absolute-domain.crt
```

While the server is running, any of these steps can be
re-run without messing up with the traffic.

## Debbugging and Troubleshooting

One way to debug/toubleshoot planb is by analyzing the running goroutines.

Planb is able to handle the USR1 signal to dump goroutines in its execution
screen:

```
$ kill -s USR1 <planb-PID>
```

## Links

* Repository & Issue Tracker: https://github.com/tsuru/planb
* Talk to us on Gitter: https://gitter.im/tsuru/tsuru
