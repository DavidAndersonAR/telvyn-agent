# Third-party notices

This document lists third-party components and source material included in or
used by Telvyn Agent. Product documentation and runtime messages intentionally
avoid comparisons with third-party products; the names below are retained only
for license compliance and source attribution.

## DDSketch

Telvyn Agent uses `github.com/DataDog/sketches-go`, distributed under the
Apache License, Version 2.0. The dependency source is available at:

https://github.com/DataDog/sketches-go

The Apache License, Version 2.0 is reproduced in the root `LICENSE` file.

## SNMP profile catalog

Part of `internal/snmp/profiles/` is transformed from the open-source NDM
profile catalog distributed in DataDog `integrations-core`:

- Source: https://github.com/DataDog/integrations-core
- Source path: `snmp/datadog_checks/snmp/data/default_profiles/`
- Imported revision: `6e9d2c5fd681d34d7f862e5fbb396792e653e771`
- License: BSD 3-Clause

Copyright (c) 2016, Datadog, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of integrations-core nor the names of its contributors may
   be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The imported source snapshot and its original license are retained in
`tools/convert-snmp-profiles/upstream-source/` for reproducibility.

## Linux installation script

`packaging/install.sh` uses installation patterns inspired by the open-source
DataDog Linux Agent installation script:

https://github.com/DataDog/agent-linux-install-script

That project is distributed under the Apache License, Version 2.0. The Telvyn
script does not include installation telemetry, product flavors or legacy
upgrade paths from that project.
