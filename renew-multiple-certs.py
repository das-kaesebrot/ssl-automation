#!/usr/bin/env python3

import argparse
import logging
import subprocess
import sys
from renew_cert import run_renewal, reload_systemd_unit, ARG_SYSTEMD_UNIT, ARG_SILENT


def main():
    parser = argparse.ArgumentParser(
        description="Acquire/renew multiple Let's Encrypt certificates via certbot (to be run as a cron job)",
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
    parser.add_argument("-m", "--mail", help="", type=str, required=True)
    parser.add_argument("-D", "--domains", nargs="*", required=True)
    parser.add_argument(
        "--systemd-unit",
        type=str,
        help="systemd unit to reload after running renewal (as long as --no-reload isn't passed)",
        default=ARG_SYSTEMD_UNIT,
    )

    args = parser.parse_args()

    try:
        logging.basicConfig(
            format="[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
            level=logging.DEBUG,
        )
        logger = logging.getLogger()

        if args.silent:
            logger.setLevel(logging.WARN)

        for domain in args.domains:
            run_renewal(
                mail=args.mail, domain=domain, silent=args.silent, no_reload=True
            )

        reload_systemd_unit(ARG_SYSTEMD_UNIT)

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
