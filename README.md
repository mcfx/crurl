# crurl
Wrapper of Chromium Network Stack, with a simple curl-like CLI (just a subset)

```
Usage: crurl [options...] <url>

Options:
     --compressed                     No actual meaning
 -d, --data <data>                    HTTP POST data
     --data-binary <data>             HTTP POST data
     --data-raw <data>                HTTP POST data
 -H, --header <header>                Pass custom header(s) to server
 -h, --help                           Show this message
 -k, --insecure                       Allow insecure server connections when using SSL
 -x, --proxy [protocol://]host[:port] Use this proxy
 -u, --user <user:password>           Server user and password
```