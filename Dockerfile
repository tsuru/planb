# Copyright 2015 tsuru authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

FROM alpine:3.11.3
RUN apk update && apk add libc6-compat

ADD planb /bin/planb
EXPOSE 8080
ENTRYPOINT ["/bin/planb"]
