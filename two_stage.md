# Two-Stage Attestation for Containerized Workloads on Intel TDX

## Overview

Intel TDX provides hardware-enforced isolation for virtual machines (called Trust Domains, or TDs) and a remote attestation mechanism that allows external parties to verify the software stack running inside a TD. A key architectural feature of TDX is the availability of **Runtime Measurement Registers (RTMRs)** — hardware registers that guest software can extend at runtime, after the initial VM launch measurements are finalized.

This document describes a **two-stage attestation model** that leverages TDX's measurement architecture to decouple a reusable base VM image from an application-specific container image. The base image provides the trusted runtime infrastructure (kernel, container runtime, attestation tooling), while the container image carries the actual workload. Both stages are captured in the TDX attestation report, enabling a remote verifier to confirm not only the integrity of the base platform but also the identity of the specific workload running on it.

## TDX Measurement Architecture

TDX provides the following measurement registers, all of which are included in the signed attestation report (the "Quote"):

| Register | Set By | Contents |
|----------|--------|----------|
| **MRTD** | TDX Module at TD creation | Hash chain of all initial memory pages loaded into the TD by the VMM — in practice, this covers the virtual firmware (TDVF/OVMF). |
| **RTMR[0]** | Firmware (TDVF) | Firmware configuration, Secure Boot variables, and firmware-level measurements. |
| **RTMR[1]** | Bootloader / Firmware | Kernel image hash, initrd hash, and kernel command line (including dm-verity root hash if used). |
| **RTMR[2]** | Guest OS / Application | Available for OS-level runtime measurements (e.g., IMA, container image digests). |
| **RTMR[3]** | Guest OS / Application | Available for application-level runtime measurements. |

Each RTMR supports a hash-extend operation: `RTMR_new = SHA384(RTMR_old || digest)`. This is a one-way accumulation — values can be extended but never rolled back, mirroring the semantics of TPM PCRs.

Additionally, the attestation report includes a 64-byte **REPORTDATA** field, set by the guest at quote-generation time. This is typically used to bind the attestation to a specific cryptographic identity (e.g., a TLS public key hash), preventing relay attacks.

## The Two Stages

### Stage 1: Base Image (MRTD + RTMR[0] + RTMR[1])

The base image is a purpose-built, minimal VM image consisting of:

- **TDVF firmware** — the TDX-aware UEFI implementation (a variant of OVMF). Measured into MRTD by the TDX Module at TD creation.
- **Linux kernel** — a minimal, hardened kernel with TDX guest support, dm-verity, and the configfs-tsm interface for attestation. Measured into RTMR[1] by the firmware/bootloader.
- **Initrd** — initial ramdisk that sets up dm-verity and pivots to the root filesystem. Measured into RTMR[1].
- **Root filesystem** — a read-only, dm-verity-protected filesystem containing:
  - A container runtime (e.g., `crun`, `youki`, or `podman`)
  - An RTMR-extend helper (for measuring container images before launch)
  - Attestation tooling (e.g., libraries for generating TDX quotes via configfs-tsm)
  - An RA-TLS library for establishing attested TLS channels

The dm-verity root hash is embedded in the kernel command line, which is itself measured into RTMR[1]. This means the integrity of the entire base filesystem is transitively captured: if any file on the rootfs is tampered with, dm-verity returns an I/O error, and the hash chain back to RTMR[1] ensures the verifier can detect any substitution of the rootfs.

The base image is **generic and reusable** — it does not contain any workload-specific code. It can be audited once, and its expected measurement values (MRTD, RTMR[0], RTMR[1]) can be published as a stable reference.

### Stage 2: Container Image (RTMR[2])

The workload is delivered as a standard OCI container image, provided to the TD at runtime (pulled from a registry, injected via a virtio disk, etc.). Before the container is started, the base image's container launch tooling performs the following:

1. **Compute the image manifest digest** — the OCI content-addressable image ID, which is a SHA-256 hash over the image configuration and all layer digests. This digest deterministically identifies the container image.
2. **Extend RTMR[2]** with the image manifest digest, via `TDCALL[TDG.MR.RTMR.EXTEND]` (exposed to userspace through the Linux configfs-tsm interface or the `/dev/tdx_guest` device).
3. **Start the container** — the container runtime unpacks and executes the image.

After extension, RTMR[2] reflects the specific workload running inside the TD. The attestation report now contains a complete chain: MRTD + RTMR[0-1] identify the base platform, and RTMR[2] identifies the workload.

Optionally, if the container image is **encrypted**, the base image can include an attestation agent that first attests the base TD to a Key Broker Service (KBS), retrieves the image decryption key, decrypts the image inside the TD, and then extends RTMR[2] with the decrypted image's manifest digest. The image contents never leave the TD boundary in plaintext.

## Attestation and Verification Flow

### Quote Generation (inside the TD)

The workload (or a sidecar attestation service) generates a TDX Quote by:

1. Computing 64 bytes of REPORTDATA — typically `SHA384(TLS_public_key)` to bind the attestation to a TLS session.
2. Writing the REPORTDATA to the configfs-tsm interface:
   ```bash
   mkdir /sys/kernel/config/tsm/report/report0
   # Write REPORTDATA
   cat report_data.bin > /sys/kernel/config/tsm/report/report0/inblob
   # Read the signed Quote
   cat /sys/kernel/config/tsm/report/report0/outblob > quote.bin
   # Read the certificate chain
   cat /sys/kernel/config/tsm/report/report0/certs > certs.pem
   rmdir /sys/kernel/config/tsm/report/report0
   ```
3. The TDX module invokes `SEAMREPORT` to generate a Report structure (MAC'd with a platform-local key), which is then converted into a remotely-verifiable Quote by the TD Quoting Enclave (an SGX enclave running on the same platform). The Quote is signed with an ECDSA attestation key whose certificate chain roots to Intel.

### Quote Verification (by the relying party)

A remote verifier (e.g., a data provider in a federated computation) performs the following checks:

1. **Signature chain**: Verify the Quote's ECDSA signature → Attestation Key Certificate (signed by PCK) → PCK Certificate (signed by Intel CA). Revocation lists (CRLs) are checked at each level.
2. **TCB version**: Confirm that the platform's TCB (CPU microcode SVN, SEAMLDR SVN, TDX Module SVN) meets the minimum acceptable threshold. This ensures known vulnerabilities have been patched.
3. **MRTD**: Compare against the expected value for the known TDVF firmware build.
4. **RTMR[0]**: Compare against the expected value for the firmware configuration.
5. **RTMR[1]**: Compare against the expected value for the known kernel + initrd + dm-verity root hash. This transitively covers the entire base rootfs.
6. **RTMR[2]**: Compare against the expected value for the approved container image digest.
7. **REPORTDATA**: Verify that it contains the hash of the TLS public key presented by the TD, binding the attestation to the current session.
8. **TD Attributes**: Confirm expected settings (e.g., debug mode is disabled, SEPT_VE_DISABLE is set).

If all checks pass, the verifier has cryptographic assurance that the TD is running on genuine TDX hardware with up-to-date firmware, the base image is the expected audited build, and the workload container is the specific approved image — all bound to the TLS session they're communicating over.

## RA-TLS Integration

Remote Attestation TLS (RA-TLS) embeds the TDX Quote directly into a self-signed X.509 certificate as a custom extension. The workload generates an ephemeral TLS keypair, places the public key hash in REPORTDATA, obtains a Quote, and constructs a certificate containing the Quote. When a client connects, it extracts and verifies the Quote from the certificate before trusting the TLS channel.

This eliminates the need for a separate attestation protocol — attestation is part of the TLS handshake. The client verifies:

- The Quote is valid (signature chain, TCB, measurements)
- The REPORTDATA matches the TLS public key in the certificate
- Therefore, the TLS endpoint is running inside a TD with the attested software stack

For the two-stage model, the RA-TLS verifier checks all RTMRs as described above. The verification policy can be expressed as a simple allowlist of acceptable (MRTD, RTMR[0], RTMR[1], RTMR[2]) tuples.

## Operational Benefits

**Independent update cycles.** The base image and the container image can be updated independently. A kernel security patch changes RTMR[0-1] but not RTMR[2]; a workload code change updates RTMR[2] but not the base measurements. Verifiers update only the relevant expected values in their attestation policy.

**Reusable, auditable base.** The base image can be standardized, published, and audited by multiple parties. Different workloads share the same base, reducing the audit surface. Only the container image (RTMR[2]) varies per deployment.

**CI/CD integration.** A build pipeline produces a container image with a deterministic digest. This digest is published alongside the deployment, and verifiers can independently confirm it by pulling the same image from the registry. No full VM image rebuild is required for workload changes.

**Multi-party verification.** In a federated or multi-party computation setting, each data provider can independently verify the attestation against their own policy. They approve a specific container image digest (RTMR[2]) representing the computation they've audited, while trusting the base image measurements as a shared foundation.

## Comparison with SEV-SNP

AMD SEV-SNP does not provide hardware RTMRs. Its attestation report contains a single `MEASUREMENT` field that is frozen at VM launch. Runtime measurement on SEV-SNP requires a virtual TPM (vTPM) running inside the SVSM (Secure VM Service Module) at VMPL0, adding software to the TCB and requiring a two-layered attestation (hardware report + vTPM quote). TDX's native RTMRs provide a simpler, hardware-rooted path for the two-stage model described here.

| Capability | Intel TDX | AMD SEV-SNP |
|---|---|---|
| Launch measurement | MRTD (hardware) | MEASUREMENT (AMD-SP) |
| Runtime-extendable registers | 4 RTMRs (hardware TDCALL) | None natively; requires SVSM vTPM |
| Container digest attestation | Extend RTMR via configfs-tsm | Extend vTPM PCR via SVSM |
| Additional TCB for runtime measurement | None (hardware instruction) | SVSM + vTPM code at VMPL0 |

## Tools and Libraries

- **configfs-tsm** (Linux 6.7+): Cross-vendor kernel interface for generating attestation reports. Supports TDX quote generation and RTMR extension from userspace.
- **go-tdx-guest** (Google): Go library wrapping configfs-tsm for quote generation, RTMR extension, and quote verification.
- **go-configfs-tsm** (Google): Lower-level Go library for the configfs-tsm interface.
- **measured-boot-tools** (Fraunhofer AISEC): Tools for pre-computing expected MRTD and RTMR values from firmware, kernel, command line, and configuration parameters. Useful for generating reference values for attestation policies.
- **CoCo guest-components**: The Confidential Containers project's attestation-agent, confidential-data-hub, and image-rs libraries can be used standalone (without Kubernetes) to handle attestation flows, secret retrieval, and container image pulling inside a CVM.

## References

- Intel TDX Module Specification: [intel.com/tdx](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html)
- configfs-tsm kernel documentation: `Documentation/ABI/testing/configfs-tsm` in the Linux source tree
- Confidential Containers project: [confidentialcontainers.org](https://confidentialcontainers.org)
- Fraunhofer measured-boot-tools: [github.com/Fraunhofer-AISEC/measured-boot-tools](https://github.com/Fraunhofer-AISEC/measured-boot-tools)
- Google go-tdx-guest: [github.com/google/go-tdx-guest](https://github.com/google/go-tdx-guest)
