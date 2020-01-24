# Copyright 2015 tsuru authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

FROM alpine:3.11.3
RUN apk update && apk add libc6-compat

ADD planb /bin/planb
ADD start.sh /bin/start.sh
EXPOSE 8000
ENTRYPOINT ["sh", "/bin/start.sh"]
CMD ["--listen","0.0.0.0:8000","--metrics-address","0.0.0.0:9000","--access-log","/tmp/access.log","--read-redis-host","tsuru-16-ro.eduk.vpc","--write-redis-host","tsuru-16-rw.eduk.vpc","--request-timeout","60"]
