# Third-party AWG generator attribution

The AWG obfuscation parameter generator is based on the work of
[VAIPROG/Any-Tech-ARCHITECT](https://github.com/VAIPROG/Any-Tech-ARCHITECT)
by VAI_PROG (Vadim). We are grateful to the author; the project is the
reference for how these parameters are chosen.

What is adapted from it:

- `orchestrator/src/wgoctopus_orch/awgparams.py` — algorithms for Jc/Jmin/Jmax,
  S1–S4, H1–H4 ranges and the AWG 3.x fields.
- `orchestrator/src/wgoctopus_orch/awgcps.py` — I1–I5 CPS mimicry profiles.
- The Generate section of `/ui/instances/new` — the parameter explanations and
  selection guidance follow the original's texts and FAQ. The page links to the
  original project.

Copyright (c) 2026 VAI_PROG (Vadim). Licensed under the MIT License; the
copyright and permission notice must be included with copies or substantial
portions of the software. The full license text is in the repository's
[NOTICE](../NOTICE).
