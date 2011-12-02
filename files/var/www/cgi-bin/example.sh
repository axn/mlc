#!/bin/sh
cat << EOF
Content-Type: text/html

<html>
<head>
<title>cgi shell scripting example</title>
</head>
<body>
<h1>Stats for this computer</h1>
EOF
echo Date: $(date) "<br />"
echo Uptime: $(uptime) "<br />"
cat << EOF
</body>
</html>
EOF
