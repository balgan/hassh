#!/usr/bin/env python3
# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
"""Run hassh straight from a checkout: python3 hassh.py -r capture.pcap"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from hassh.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
