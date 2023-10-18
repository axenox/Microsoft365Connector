# Troubleshooting Azure connections

## Connection errors

### cURL error 60: SSL certificate problem: unable to get local issuer certificate

On many Windows servers, the default SSL root certificates do not work with Azure. The solution is to download the current ´cacert.pem´ file from a trustworthy source like this one: https://curl.se/docs/caextract.html. Save this file to some location easily accessible from the PHP installation folder and/uncomment add the following line to `php.ini`:

```
curl.cainfo = C:\your\path\cacert.pem
```