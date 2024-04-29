# certbot-scripts

This folder contains scripts required for auto-renewal of Let's Encrypt issued certificates.

To use, either run `./renew_cert.py` directly or install a cron job for `./renew-multiple-certs.py` like so:

```cron
0 4 * * * root /path/to/script/renew-multiple-certs.py -s -m mymail@example.com -D domain1.example.com domain2.example.com
```

To see script usage, run the following commands:

```bash
./renew_cert.py -h
```
```bash
./renew-multiple-certs.py -h
```