# ns-ovh.sslip.io OVH Warsaw Dedicated Server Nameserver

## Getting OVH API Credentials

1. Log into the [OVH API console](https://api.us.ovhcloud.com/createApp/)
2. Create an application — note the **Application Key** and **Application Secret**
3. Generate a **Consumer Key** with curl (they only last a maximum of 30 days):

```bash
curl -s -X POST https://api.us.ovhcloud.com/1.0/auth/credential \
  -H "Content-Type: application/json" \
  -H "X-Ovh-Application: dmUzEgjQwBIfJbUf" \
  -d '{"accessRules":[{"method":"GET","path":"/*"},{"method":"PUT","path":"/*"}]}' \
  | jq .
```

Visit the `validationUrl` from the response to authorize the key, then save the `consumerKey`.

## Initial Setup

```bash
export TF_VAR_ovh_application_key=dmUzEgjQwBIfJbUf
export TF_VAR_ovh_application_secret=YOUR_APPLICATION_SECRET
export TF_VAR_ovh_consumer_key=YOUR_CONSUMER_KEY
```

## Misc

Find out which IP addresses are available:

```bash
TS=$(date +%s)
URL=https://api.us.ovhcloud.com/1.0/ip
SIG='$1$'$(echo -n "${TF_VAR_ovh_application_secret}+${TF_VAR_ovh_consumer_key}+GET+${URL}++${TS}" | sha1sum | cut -d' ' -f1)

curl -s "$URL" \
  -H "X-Ovh-Application: $TF_VAR_ovh_application_key" \
  -H "X-Ovh-Consumer: $TF_VAR_ovh_consumer_key" \
  -H "X-Ovh-Timestamp: $TS" \
  -H "X-Ovh-Signature: $SIG"
```
