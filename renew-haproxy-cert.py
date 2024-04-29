#!/usr/bin/env python3

# Acquires or renews a single certificate via Let's Encrypt and writes it out as a HAProxy compatible certificate.
# First the SSL certificate is checked for validity >= <expiry-days>. If it's still valid for more than <expiry-days>, we exit early.
# --force overrides that behaviour so the check isn't performed
# Uses the standalone webserver configuration in certbot, spawning at port 8888.
# WARNING: HAProxy has to be configured to redirect HTTP traffic to /.well-known/acme-challenge/ to the certbot standalone webserver

import os
import sys
import argparse
import subprocess
import logging

SECONDS_PER_DAY = 86400


def main():
    logging.basicConfig(
        format="[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
        level=logging.DEBUG,
    )
    logger = logging.getLogger()

    # Check if being run as root
    if not os.geteuid() == 0:
        logger.error("You need to execute this script as root")
        sys.exit(3)

    try:
        abs_folder_path = os.path.abspath(os.path.dirname(__file__))
        parser = argparse.ArgumentParser(
            description="Acquire/renew Let's Encrypt certificates via certbot"
        )

        parser.add_argument(
            "-s",
            "--silent",
            action="store_true",
            help="Suppress non-essential logging (so that it runs silently in a cron job)",
            required=False,
            default=False,
        )
        parser.add_argument(
            "-f",
            "--force",
            action="store_true",
            help="Force a renewal even if cert is valid for longer than <expiry-days>",
            required=False,
        )
        parser.add_argument(
            "--no-reload",
            action="store_true",
            help="Don't reload HAProxy systemd service after acquiring cert. Default: false",
            required=False,
            default=False,
        )
        parser.add_argument(
            "-m",
            "--mail",
            type=str,
            help="Mail address to use for Let's Encrypt",
            required=True,
        )
        parser.add_argument(
            "-d", "--domain", type=str, help="Domain to renew cert for", required=True
        )
        parser.add_argument(
            "--expiry-days",
            type=int,
            help="Minimum validity days before cert is renewed. Default: 30",
            required=False,
            default=30,
        )
        parser.add_argument(
            "--cert-dir",
            type=str,
            help="Base directory for HAProxy certificates. Default: '/etc/ssl/private'",
            default="/etc/ssl/private",
            required=False,
        )

        parser.add_argument(
            "--le-cert-dir",
            type=str,
            help="Let's Encrypt base directory for acquired certificates. Default: '/etc/letsencrypt/live'",
            default="/etc/letsencrypt/live",
            required=False,
        )

        parser.add_argument(
            "--challenge",
            type=str,
            help="ACME challenge to perform (certbot arg). Default: '--standalone'",
            default="--standalone",
        )
        parser.add_argument(
            "--certbot-args",
            type=str,
            help="Additional args to pass to certbot. Default: '--preferred-challenges http --http-01-port 8888'",
            default="--preferred-challenges http --http-01-port 8888",
        )

        args = parser.parse_args()

        if args.silent:
            logger.setLevel(logging.WARN)

        expiry_seconds = args.expiry_days * SECONDS_PER_DAY

        certpath_haproxy = os.path.join(args.cert_dir.rstrip("/"), f"{args.domain}.pem")

        assert isinstance(expiry_seconds, int)

        # only run openssl check if we're not forcing a renewal
        if not args.force:
            # check whether the cert is valid for longer than the given expiry time (has to be given in seconds to openssl)
            openssl_args = [
                "openssl",
                "x509",
                "-checkend",
                str(expiry_seconds),
                "-noout",
                "-in",
                certpath_haproxy,
            ]
            logger.debug(f"Executing command {openssl_args}")
            openssl_result = subprocess.run(openssl_args, capture_output=True)
            logger.debug(f"stdout=\n{openssl_result.stdout.decode()}")
            logger.debug(f"stderr=\n{openssl_result.stderr.decode()}")
            try:
                # if this returned with an exit code of 0, the cert is still valid. Nothing to do for now.
                openssl_result.check_returncode()
                return 0
            except subprocess.CalledProcessError as e:
                pass

        certbot_args = [
            "certbot",
            "certonly",
            "--force-renewal",
            "--email",
            args.mail,
            "-d",
            args.domain,
            "--agree-tos",
            "--no-eff-email",
            args.challenge,
            *(args.certbot_args.split(" ")),
        ]

        logger.debug(f"Executing command {certbot_args}")

        certbot_result = subprocess.run(certbot_args, capture_output=True)
        certbot_result.check_returncode()
        logger.debug(f"stdout=\n{certbot_result.stdout.decode()}")
        logger.debug(f"stderr=\n{certbot_result.stderr.decode()}")

        certpath_le_fullchain = os.path.join(
            args.le_cert_dir.rstrip("/"), args.domain, "fullchain.pem"
        )
        certpath_le_privkey = os.path.join(
            args.le_cert_dir.rstrip("/"), args.domain, "privkey.pem"
        )

        buf_fullchain: bytes = None
        buf_privkey: bytes = None

        logger.debug(
            f"Concatenating '{certpath_le_fullchain}' and '{certpath_le_privkey}' to '{certpath_haproxy}'"
        )

        # concatenate cert files for haproxy, this is required!
        with open(certpath_le_fullchain, "rb") as f:
            buf_fullchain = f.read()

        with open(certpath_le_privkey, "rb") as f:
            buf_privkey = f.read()

        with open(certpath_haproxy, "wb") as f:
            written_bytes = f.write(buf_fullchain)
            written_bytes += f.write(buf_privkey)

            logger.debug(f"Wrote {written_bytes} to '{certpath_haproxy}'")

        # Reload HAProxy service
        if not args.no_reload:
            logger.debug("Reloading HAProxy systemd service")

            systemctl_result = subprocess.run(
                ["systemctl", "reload", "haproxy"], capture_output=True
            )
            systemctl_result.check_returncode()

    except subprocess.CalledProcessError as e:
        logger.exception("Error while executing subprocess")
        # echo out stdout and stderr from the failed command
        sys.stdout.write(e.stdout.decode())
        sys.stderr.write(e.stderr.decode())
        sys.exit(2)

    except Exception as e:
        logger.exception("Generic exception occured")
        sys.exit(1)


if __name__ == "__main__":
    main()
