PlanB: a distributed HTTP and websocket proxy
=================================================

[![Build Status](https://drone.io/github.com/tsuru/planb/status.png)](https://drone.io/github.com/tsuru/planb/latest)
[![Build Status](https://travis-ci.org/tsuru/planb.svg?branch=master)](https://travis-ci.org/tsuru/planb)

What Is It?
-----------

PlanB is a HTTP and websocket proxy backed by Redis and inspired by
[Hipache](https://github.com/dotcloud/hipache).

It aims to be fully compatible with Hipache when Redis is used as a backend.
The same format is used for all keys stored in Redis so migrating from Hipache
to PlanB should be completely seamless. The process should be as simple as
replacing Hipache's executable for PlanB.

Start-up flags
--------------

The following flags are available for configuring PlanB on start-up:

- ``--listen/-l``: the address to which PlanB will bind. Default value is
  ``0.0.0.0:8989``.
- ``--read-redis-host``: Redis host of the server which contains application
  addresses. Default value is ``localhost``.
- ``--read-redis-port``: Redis port of the server which contains application
  addresses. Default value is ``6379``.
- ``--write-redis-host``: Redis host of the server which PlanB will use for
  publishing dead backends. Default value is ``localhost``.
- ``--write-redis-port``: Redis port of the server which which PlanB will use
  for publishing dead backends. Default value is ``6379``.
- ``--access-log``: File path where access log will be written. If value equals
  ``syslog`` log will be sent to local syslog. Default value is
  ``./access.log``.
- ``--request-timeout``: Total backend request timeout in seconds. Default
  value is ``30``.
- ``--dial-timeout``: Dial backend request timeout in seconds. Default value is
  ``10``.
- ``--dead-backend-time``: Time in seconds a backend will remain disabled after
  a network failure. Default value is ``30``.
- ``--flush-interval``: Time in milliseconds to flush the proxied request.
  Default value is ``10``.
