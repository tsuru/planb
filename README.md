PlanB: a distributed HTTP and websocket proxy
=================================================

[![Build Status](https://drone.io/github.com/tsuru/planb/status.png)](https://drone.io/github.com/tsuru/planb/latest)

What Is It?
-----------

PlanB is a HTTP and websocket proxy backed by Redis and inspired by
[Hipache](https://github.com/dotcloud/hipache).

It aims to be fully compatible with Hipache when Redis is used as a backend.
The same format is used for all keys stored in Redis so migrating from Hipache
to PlanB should be completely seamless. The process should be as simple as
replacing Hipache's executable for PlanB.
