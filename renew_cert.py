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

# default values
ARG_SILENT = False
ARG_FORCE = False
ARG_NO_RELOAD = False
ARG_EXPIRY_DAYS = 30
ARG_CERT_DIR = "/etc/ssl/private"
ARG_LE_CERT_DIR = "/etc/letsencrypt/live"
ARG_CHALLENGE = "--standalone"
ARG_CERTBOT_ARGS = "--preferred-challenges http --http-01-port 8888"
ARG_SYSTEMD_UNIT = "haproxy.service"
ARG_NO_CONCAT = False
ARG_CERT_OWNER = None
ARG_CERT_GROUP = None


def main():
    abs_folder_path = os.path.abspath(os.path.dirname(__file__))
    parser = argparse.ArgumentParser(
        description="Acquire/renew Let's Encrypt certificates via certbot",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-s",
        "--silent",
        action="store_true",
        help="Suppress non-essential logging (so that it runs silently in a cron job)",
        required=False,
        default=ARG_SILENT,
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Force a renewal even if cert is valid for longer than <expiry-days>",
        required=False,
        default=ARG_FORCE,
    )
    parser.add_argument(
        "--no-reload",
        action="store_true",
        help="Don't reload systemd service after acquiring cert.",
        required=False,
        default=ARG_NO_RELOAD,
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
        help="Minimum validity days before cert is renewed.",
        required=False,
        default=ARG_EXPIRY_DAYS,
    )
    parser.add_argument(
        "--cert-dir",
        type=str,
        help="Base directory for certificates to be concatenated/written into.",
        default=ARG_CERT_DIR,
        required=False,
    )

    parser.add_argument(
        "--le-cert-dir",
        type=str,
        help="Let's Encrypt base directory for acquired certificates.",
        default=ARG_LE_CERT_DIR,
        required=False,
    )

    parser.add_argument(
        "--challenge",
        type=str,
        help="ACME challenge to perform (certbot arg).",
        default=ARG_CHALLENGE,
    )
    parser.add_argument(
        "--certbot-args",
        type=str,
        help="Additional args to pass to certbot, formatted as one string.",
        default=ARG_CERTBOT_ARGS,
    )
    parser.add_argument(
        "--systemd-unit",
        type=str,
        help="systemd unit to reload after running renewal (as long as --no-reload isn't passed)",
        default=ARG_SYSTEMD_UNIT,
    )
    parser.add_argument(
        "--no-concat",
        help="Don't concatenate fullchain and key into one file, just copy to a subdirectory by the cert name",
        action="store_true",
        default=ARG_NO_CONCAT,
    )
    parser.add_argument(
        "--cert-owner",
        type=str,
        help="Owner for the target certificate(s)",
        default=ARG_CERT_OWNER,
    )
    parser.add_argument(
        "--cert-group",
        type=str,
        help="Group for the target certificate(s)",
        default=ARG_CERT_GROUP,
    )

    args = parser.parse_args()
    run_renewal(**vars(args))


def reload_systemd_unit(unit_name: str):
    logging.getLogger().debug(f"Reloading systemd service '{unit_name}'")

    systemctl_result = subprocess.run(
        ["systemctl", "reload", unit_name], capture_output=True
    )
    systemctl_result.check_returncode()


def copy_certs(
    certpath_target_root: str,
    domain: str,
    cert_owner: str,
    cert_group: str,
    certpath_le_fullchain: str,
    certpath_le_privkey: str,
):

    logger = logging.getLogger()

    certpath_target_dir = os.path.join(certpath_target_root.rstrip("/"), domain)

    from shutil import copyfile, chown

    logger.info(
        f"Copying generated fullchain and privkey to output folder '{certpath_target_dir}'"
    )

    if not os.path.isdir(certpath_target_dir):
        logger.info(f"Folder '{certpath_target_dir}' doesn't exist yet, creating it")
        os.mkdir(certpath_target_dir)

        if cert_owner:
            logger.debug(
                f"Setting '{certpath_target_dir}' ownership to {cert_owner}{':' + cert_group if cert_group else ''}"
            )
            chown(certpath_target_dir, cert_owner, cert_group)

    certpath_fullchain_target = os.path.join(certpath_target_dir, "fullchain.pem")
    logger.debug(f"Copying '{certpath_le_fullchain}' to '{certpath_fullchain_target}'")
    copyfile(certpath_le_fullchain, certpath_fullchain_target)
    certpath_privkey_target = os.path.join(certpath_target_dir, "privkey.pem")
    logger.debug(f"Copying '{certpath_le_privkey}' to '{certpath_privkey_target}'")
    copyfile(certpath_le_privkey, certpath_privkey_target)

    if cert_owner:
        logger.debug(
            f"Setting file ownership to {cert_owner}{':' + cert_group if cert_group else ''}"
        )
        chown(certpath_fullchain_target, cert_owner, cert_group)
        chown(certpath_privkey_target, cert_owner, cert_group)
        os.chmod(certpath_privkey_target, 0o600)


def run_renewal(
    mail: str,
    domain: str,
    silent: bool = ARG_SILENT,
    force: bool = ARG_FORCE,
    no_reload: bool = ARG_NO_RELOAD,
    expiry_days: int = ARG_EXPIRY_DAYS,
    cert_dir: str = ARG_CERT_DIR,
    le_cert_dir: str = ARG_LE_CERT_DIR,
    challenge: str = ARG_CHALLENGE,
    certbot_args: str = ARG_CERTBOT_ARGS,
    systemd_unit: str = ARG_SYSTEMD_UNIT,
    no_concat: bool = ARG_NO_CONCAT,
    cert_owner: str = ARG_CERT_OWNER,
    cert_group: str = ARG_CERT_GROUP,
):
    try:
        logging.basicConfig(
            format="[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
            level=logging.DEBUG,
        )
        logger = logging.getLogger()

        # Check if being run as root
        if not os.geteuid() == 0:
            logger.error("You need to execute this script as root")
            sys.exit(3)

        if silent:
            logger.setLevel(logging.WARN)

        logger.debug(f"Renewing cert for '{domain}'")

        expiry_seconds = expiry_days * SECONDS_PER_DAY

        le_certpath = os.path.join(le_cert_dir.rstrip("/"), domain, "fullchain.pem")

        skip_certbot = False

        assert isinstance(expiry_seconds, int)

        # check whether the cert is valid for longer than the given expiry time (has to be given in seconds to openssl)
        openssl_args = [
            "openssl",
            "x509",
            "-checkend",
            str(expiry_seconds),
            "-noout",
            "-in",
            le_certpath,
        ]
        logger.debug(f"Executing command {openssl_args}")
        openssl_result = subprocess.run(openssl_args, capture_output=True)
        logger.debug(f"stdout=\n{openssl_result.stdout.decode()}")
        logger.debug(f"stderr=\n{openssl_result.stderr.decode()}")
        try:
            # if this returned with an exit code of 0, the cert is still valid. Nothing to do for now.
            openssl_result.check_returncode()
            skip_certbot = True
        except subprocess.CalledProcessError as e:
            pass

        # only run certbot if forced or not skipped
        if force or not skip_certbot:
            certbot_args = [
                "certbot",
                "certonly",
                "--force-renewal",
                "--email",
                mail,
                "-d",
                domain,
                "--agree-tos",
                "--no-eff-email",
                challenge,
                *(certbot_args.split(" ")),
            ]

            logger.debug(f"Executing command {certbot_args}")

            certbot_result = subprocess.run(certbot_args, capture_output=True)
            certbot_result.check_returncode()
            logger.debug(f"stdout=\n{certbot_result.stdout.decode()}")
            logger.debug(f"stderr=\n{certbot_result.stderr.decode()}")

        certpath_le_fullchain = os.path.join(
            le_cert_dir.rstrip("/"), domain, "fullchain.pem"
        )
        certpath_le_privkey = os.path.join(
            le_cert_dir.rstrip("/"), domain, "privkey.pem"
        )

        if no_concat:
            copy_certs(
                certpath_target_root=cert_dir,
                domain=domain,
                cert_owner=cert_owner,
                cert_group=cert_group,
                certpath_le_fullchain=certpath_le_fullchain,
                certpath_le_privkey=certpath_le_privkey,
            )

        else:
            certpath_target = os.path.join(cert_dir.rstrip("/"), f"{domain}.pem")

            buf_fullchain: bytes = None
            buf_privkey: bytes = None

            logger.debug(
                f"Concatenating '{certpath_le_fullchain}' and '{certpath_le_privkey}' to '{certpath_target}'"
            )
            # concatenate cert files for haproxy, this is required!
            with open(certpath_le_fullchain, "rb") as f:
                buf_fullchain = f.read()

            with open(certpath_le_privkey, "rb") as f:
                buf_privkey = f.read()

            with open(certpath_target, "wb") as f:
                written_bytes = f.write(buf_fullchain)
                written_bytes += f.write(buf_privkey)

                logger.debug(f"Wrote {written_bytes} byte to '{certpath_target}'")

            if cert_owner:
                from shutil import chown

                logger.debug(
                    f"Setting '{certpath_target}' ownership to {cert_owner}{':' + cert_group if cert_group else ''}"
                )

                chown(certpath_target, cert_owner, cert_group)

        # Reload HAProxy service
        if not no_reload:  # double negatives are terrible
            reload_systemd_unit(systemd_unit)

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
