# Copyright 2015 tsuru authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

FROM alpine:3.2
ADD planb /bin/planb
EXPOSE 8080
ENTRYPOINT ["/bin/planb"]
