GoHipache: a distributed HTTP and websocket proxy
=================================================

[![Build Status](https://drone.io/github.com/cezarsa/gohipache/status.png)](https://drone.io/github.com/cezarsa/gohipache/latest)

What Is It?
-----------

GoHipache is an HTTP and websocket proxy backed by Redis and inspired by
[Hipache](https://github.com/dotcloud/hipache).

It aims to be fully compatible with Hipache when Redis is used as a backend.
The same format is used for all keys stored in Redis so migrating from Hipache
to GoHipache should be completely seamless. The process should be as simple as
replacing Hipache's executable for GoHipache.
