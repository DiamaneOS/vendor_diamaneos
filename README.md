# DiamaneOS product configuration

Install this repository at `vendor/diamaneos` in the Android source workspace.
Device products inherit `product.mk` after their framework and hardware inputs.

This repository owns shared product identity. Device configuration, generated
hardware inputs and kernel artifacts belong to their respective repositories.
Upstream `OFFICIAL_BUILD` must be unset: it selects upstream delivery identity.
This initial configuration defines no update service or release endpoint.

Original code is Apache-2.0; see LICENSE.
