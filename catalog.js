// Copyright (c) 2026 Confidential Containers Authors
// SPDX-License-Identifier: Apache-2.0
//
// Field catalog for the Plan B policy builder.
// Paths are the policy-input paths, after AS lifts claim-root
// `report_data` and `init_data` to siblings of the TEE object.
// A path segment that itself contains a dot is written with brackets,
// because SGX emits flat keys such as "attributes.flags".

(function (root) {
  "use strict";

  function f(path, type, desc, group, extra) {
    return Object.assign({ path: path, type: type, desc: desc, group: group }, extra || {});
  }

  const UEFI_EVENT_TYPES = [
    "EV_PREBOOT_CERT",
    "EV_POST_CODE",
    "EV_UNUSED",
    "EV_NO_ACTION",
    "EV_SEPARATOR",
    "EV_ACTION",
    "EV_EVENT_TAG",
    "EV_S_CRTM_CONTENTS",
    "EV_S_CRTM_VERSION",
    "EV_CPU_MICROCODE",
    "EV_PLATFORM_CONFIG_FLAGS",
    "EV_TABLE_OF_DEVICES",
    "EV_COMPACT_HASH",
    "EV_IPL",
    "EV_IPL_PARTITION_DATA",
    "EV_NONHOST_CODE",
    "EV_NONHOST_CONFIG",
    "EV_NONHOST_INFO",
    "EV_OMIT_BOOT_DEVICE_EVENTS",
    "EV_EFI_EVENT_BASE",
    "EV_EFI_VARIABLE_DRIVER_CONFIG",
    "EV_EFI_VARIABLE_BOOT",
    "EV_EFI_BOOT_SERVICES_APPLICATION",
    "EV_EFI_BOOT_SERVICES_DRIVER",
    "EV_EFI_RUNTIME_SERVICES_DRIVER",
    "EV_EFI_GPT_EVENT",
    "EV_EFI_ACTION",
    "EV_EFI_PLATFORM_FIRMWARE_BLOB",
    "EV_EFI_HANDOFF_TABLES",
    "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
    "EV_EFI_HANDOFF_TABLES2",
    "EV_EFI_VARIABLE_BOOT2",
    "EV_EFI_HCRTM_EVENT",
    "EV_EFI_VARIABLE_AUTHORITY",
    "EV_EFI_SPDM_FIRMWARE_BLOB",
    "EV_EFI_SPDM_FIRMWARE_CONFIG",
  ];

  const DIGEST_ALGS = ["RSA", "TDES", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SM3"];

  function nf(path, type, suggestions) {
    const field = { path: path, type: type };
    if (suggestions) field.suggestions = suggestions;
    return field;
  }

  const UEFI_NESTS = [
    nf("event_type", "string", UEFI_EVENT_TYPES),
    nf("digest_matches_event", "bool"),
    nf("digests[_].alg", "string", DIGEST_ALGS),
    nf("index", "number"),
    nf("digests[_].digest", "string"),
    nf("event", "string"),
    nf("details.string", "string"),
    nf("details.unicode_name", "string"),
    nf("details.unicode_name_length", "number"),
    nf("details.variable_name", "string"),
    nf("details.variable_data", "string"),
    nf("details.variable_data_length", "number"),
    nf("details.data.domain", "string"),
    nf("details.data.operation", "string"),
    nf("details.data.content", "string"),
  ];

  const TCB_STATUS = [
    "UpToDate",
    "SWHardeningNeeded",
    "ConfigurationNeeded",
    "ConfigurationAndSWHardeningNeeded",
    "OutOfDate",
    "OutOfDateConfigurationNeeded",
    "TDRelaunchAdvised",
    "TDRelaunchAdvisedConfigurationNeeded",
  ];

  function pcrFields(prefix) {
    const fields = [];
    for (let i = 0; i < 24; i++) {
      const key = "pcr" + String(i).padStart(2, "0");
      const path = prefix ? prefix + "." + key : key;
      fields.push(
        f(
          path,
          "hex",
          "SHA-256 PCR " + i + " (" + key + ")",
          "PCR",
        ),
      );
    }
    return fields;
  }

  const tdxFields = [
    f("td_attributes.debug", "bool", "", "TD attributes"),
    f("td_attributes.septve_disable", "bool", "", "TD attributes"),
    f("td_attributes.protection_keys", "bool", "", "TD attributes"),
    f("td_attributes.key_locker", "bool", "", "TD attributes"),
    f("td_attributes.perfmon", "bool", "", "TD attributes"),

    f("quote.header.version", "hex", "", "Quote header", {
      suggestions: ["0400", "0500"],
      labels: { "0400": "Quote format V4", "0500": "Quote format V5" },
    }),
    f("quote.header.att_key_type", "hex", "", "Quote header"),
    f("quote.header.tee_type", "hex", "", "Quote header", {
      suggestions: ["81000000"],
      labels: { "81000000": "TDX" },
    }),
    f("quote.header.vendor_id", "hex", "", "Quote header", {
      suggestions: ["939a7233f79c4ca9940a0db3957f0607"],
      labels: { "939a7233f79c4ca9940a0db3957f0607": "Intel QE vendor" },
    }),
    f("quote.header.user_data", "hex", "", "Quote header"),

    f("quote.body.mr_config_id", "hex", "", "Quote body"),
    f("quote.body.mr_owner", "hex", "", "Quote body"),
    f("quote.body.mr_owner_config", "hex", "", "Quote body"),
    f("quote.body.mr_td", "hex", "", "Quote body"),
    f("quote.body.mrsigner_seam", "hex", "", "Quote body"),
    f("quote.body.report_data", "hex", "", "Quote body"),
    f("quote.body.seam_attributes", "hex", "", "Quote body"),
    f("quote.body.td_attributes", "hex", "", "Quote body"),
    f("quote.body.mr_seam", "hex", "", "Quote body"),
    f("quote.body.tcb_svn", "hex", "", "Quote body"),
    f("quote.body.xfam", "hex", "", "Quote body"),
    f("quote.body.rtmr_0", "hex", "", "Quote body"),
    f("quote.body.rtmr_1", "hex", "", "Quote body"),
    f("quote.body.rtmr_2", "hex", "", "Quote body"),
    f("quote.body.rtmr_3", "hex", "", "Quote body"),
    f("quote.body.tee_tcb_svn2", "hex", "", "Quote body"),
    f("quote.body.mr_servicetd", "hex", "", "Quote body"),
    f("quote.type", "hex", "", "Quote", {
      suggestions: ["0200", "0300"],
      labels: { "0200": "TDX 1.0", "0300": "TDX 1.5" },
    }),
    f("quote.size", "hex", "", "Quote"),

    f("advisory_ids", "list", "", "TCB", { member: "string" }),
    f("collateral_expiration_status", "string", "", "TCB", {
      suggestions: ["0"],
      labels: { "0": "Not expired" },
    }),
    f("earliest_expiration_date", "string", "", "TCB"),
    f("earliest_issue_date", "string", "", "TCB"),
    f("is_cached_keys", "bool", "", "TCB"),
    f("is_dynamic_platform", "bool", "", "TCB"),
    f("is_smt_enabled", "bool", "", "TCB"),
    f("latest_issue_date", "string", "", "TCB"),
    f("pck_crl_num", "number", "", "TCB"),
    f("platform_instance_id", "hex", "", "TCB"),
    f("platform_provider_id", "hex", "", "TCB"),
    f("root_ca_crl_num", "number", "", "TCB"),
    f("root_key_id", "hex", "", "TCB"),
    f("sgx_type", "string", "", "TCB", {
      suggestions: ["Standard", "Scalable", "Scalable with Integrity"],
    }),
    f("tcb_date", "string", "", "TCB"),
    f("tcb_eval_num", "number", "", "TCB"),
    f("tcb_status", "string", "", "TCB", { suggestions: TCB_STATUS }),
    f("tcb_date_current", "string", "", "Current TCB"),
    f("tcb_status_current", "string", "", "Current TCB", {
      suggestions: TCB_STATUS,
    }),
    f("advisory_ids_current", "list", "", "Current TCB", {
      member: "string",
    }),
    f("uefi_event_logs", "list", "", "Event log", {
      nested: true,
      nestFields: UEFI_NESTS,
    }),
  ];

  const snpFields = [
    f("chip_id", "hex", "", "Identity"),
    f("measurement", "hex", "", "Measurement"),
    f("platform_smt_enabled", "bool", "", "Platform"),
    f("platform_tsme_enabled", "bool", "", "Platform"),
    f("policy_abi_major", "number", "", "Policy"),
    f("policy_abi_minor", "number", "", "Policy"),
    f("policy_debug_allowed", "bool", "", "Policy"),
    f("policy_migrate_ma", "bool", "", "Policy"),
    f("policy_single_socket", "bool", "", "Policy"),
    f("policy_smt_allowed", "bool", "", "Policy"),
    f("reported_tcb_bootloader", "number", "", "TCB"),
    f("reported_tcb_microcode", "number", "", "TCB"),
    f("reported_tcb_snp", "number", "", "TCB"),
    f("reported_tcb_tee", "number", "", "TCB"),
  ];

  const sgxFields = [
    f("header.version", "hex", "", "Header"),
    f("header.att_key_type", "hex", "", "Header"),
    f("header.att_key_data_0", "hex", "", "Header", {
      suggestions: ["00000000"],
      labels: { "00000000": "SGX" },
    }),
    f("header.qe_svn", "hex", "", "Header"),
    f("header.pce_svn", "hex", "", "Header"),
    f("header.vendor_id", "hex", "", "Header"),
    f("header.user_data", "hex", "", "Header"),
    f("body.cpu_svn", "hex", "", "Body"),
    f("body.misc_select", "hex", "", "Body"),
    f("body.reserved1", "hex", "", "Body"),
    f("body.isv_ext_prod_id", "hex", "", "Body"),
    f(
      'body["attributes.flags"]',
      "hex",
      "",
      "Body",
    ),
    f(
      'body["attributes.xfrm"]',
      "hex",
      "",
      "Body",
    ),
    f("body.mr_enclave", "hex", "", "Body"),
    f("body.reserved2", "hex", "", "Body"),
    f("body.mr_signer", "hex", "", "Body"),
    f("body.reserved3", "hex", "", "Body"),
    f("body.config_id", "hex", "", "Body"),
    f("body.isv_prod_id", "hex", "", "Body"),
    f("body.isv_svn", "hex", "", "Body"),
    f("body.config_svn", "hex", "", "Body"),
    f("body.reserved4", "hex", "", "Body"),
    f("body.isv_family_id", "hex", "", "Body"),
    f("body.report_data", "hex", "", "Body"),
    f("platform_instance_id", "hex", "", "Platform"),
  ];

  const ccaFields = [
    f("realm.cca_realm_personalization_value", "string", "", "Realm"),
    f("realm.cca_realm_initial_measurement", "string", "", "Realm"),
    f("realm.cca_realm_extensible_measurements", "list", "", "Realm", {
      member: "string",
    }),
    f("realm.cca_realm_hash_algo_id", "string", "", "Realm"),
    f("realm.cca_realm_challenge", "string", "", "Realm"),
    f("platform.cca_platform_instance_id", "string", "", "Platform"),
    f("platform.cca_platform_implementation_id", "string", "", "Platform"),
  ];

  const csvPolicy = [
    ["nodbg", ""],
    ["noks", ""],
    ["es", ""],
    ["nosend", ""],
    ["domain", ""],
    ["csv", ""],
    ["csv3", ""],
    ["asid_reuse", ""],
    ["hsk_version", ""],
    ["cek_version", ""],
    ["api_major", ""],
    ["api_minor", ""],
  ].map(function (item) {
    return f("policy." + item[0], "number", item[1], "Guest policy");
  });

  const csvFields = csvPolicy.concat([
    f("version", "string", "", "Version", {
      suggestions: ["1", "2"],
      labels: { "1": "CSV 1", "2": "CSV 2" },
    }),
    f("user_pubkey_digest", "hex", "", "Identity"),
    f("vm_id", "hex", "", "Identity"),
    f("vm_version", "hex", "", "Identity"),
    f("mnonce", "hex", "", "Report"),
    f("measure", "hex", "", "Measurement"),
    f("anonce", "hex", "", "Signature"),
    f("sig_usage", "hex", "", "Signature"),
    f("sig_algo", "hex", "", "Signature"),
    f("serial_number", "string", "", "Identity"),
    f("build", "number", "", "Version 2"),
    f("rtmr_version", "number", "", "Version 2"),
    f("reserved0", "hex", "", "Version 2"),
    f("rtmr0", "hex", "", "Version 2"),
    f("rtmr1", "hex", "", "Version 2"),
    f("rtmr2", "hex", "", "Version 2"),
    f("rtmr3", "hex", "", "Version 2"),
    f("rtmr4", "hex", "", "Version 2"),
    f("reserved1", "hex", "", "Version 2"),
  ]);

  const seFields = [
    f("version", "number", "", "SE"),
    f("cuid", "hex", "", "SE"),
    f("tag", "hex", "", "SE"),
    f("image_phkh", "hex", "", "SE"),
    f("attestation_phkh", "hex", "", "SE"),
  ];

  const tpmFields = pcrFields("").concat([
    f("ak_public", "string", "", "TPM"),
  ]);

  const localGpuConfig = [
    "board_id",
    "chip_sku",
    "chip_sku_mod",
    "cpr_info",
    "driver_version",
    "fwid",
    "gpu_info",
    "measurement_count",
    "nvdec0_status",
    "project",
    "project_sku",
    "project_sku_mod",
    "protected_pcie_status",
    "vbios_version",
  ].map(function (name) {
    return f("config." + name, "string", name, "Local Hopper");
  });

  const gpuNras = [
    f("arch", "string", "", "Local Hopper", {
      suggestions: ["Hopper"],
    }),
    f("uuid", "string", "", "Local Hopper"),
    f("measurements", "object", "", "Local Hopper"),
  ].concat(localGpuConfig, [
    f('["x-nvidia-gpu-attestation-report-cert-chain"]["x-nvidia-cert-ocsp-status"]', "string", "", "NRAS certificate", {
      suggestions: ["good"],
    }),
    f('["x-nvidia-gpu-attestation-report-cert-chain"]["x-nvidia-cert-status"]', "string", "", "NRAS certificate", {
      suggestions: ["valid"],
    }),
    f("x-nvidia-gpu-attestation-report-cert-chain-fwid-match", "bool", "", "NRAS report"),
    f("x-nvidia-gpu-attestation-report-parsed", "bool", "", "NRAS report"),
    f("x-nvidia-gpu-attestation-report-signature-verified", "bool", "", "NRAS report"),
    f("x-nvidia-gpu-arch-check", "bool", "", "NRAS report"),
    f("x-nvidia-gpu-attestation-report-nonce-match", "bool", "", "NRAS report"),
    f("secboot", "bool", "", "NRAS configuration"),
    f("dbgstat", "string", "", "NRAS configuration", {
      suggestions: ["disabled"],
    }),
    f("x-nvidia-gpu-vbios-version", "string", "", "NRAS configuration"),
    f("x-nvidia-gpu-driver-version", "string", "", "NRAS configuration"),
    f("measres", "string", "", "NRAS measurement", {
      suggestions: ["success"],
    }),
    f('["x-nvidia-gpu-vbios-rim-cert-chain"]["x-nvidia-cert-ocsp-status"]', "string", "", "NRAS RIM", {
      suggestions: ["good"],
    }),
    f('["x-nvidia-gpu-vbios-rim-cert-chain"]["x-nvidia-cert-status"]', "string", "", "NRAS RIM", {
      suggestions: ["valid"],
    }),
    f("x-nvidia-gpu-driver-rim-fetched", "bool", "", "NRAS RIM"),
    f("x-nvidia-gpu-driver-rim-measurements-available", "bool", "", "NRAS RIM"),
    f("x-nvidia-gpu-driver-rim-schema-validated", "bool", "", "NRAS RIM"),
    f("x-nvidia-gpu-driver-rim-signature-verified", "bool", "", "NRAS RIM"),
    f("x-nvidia-gpu-driver-rim-version-match", "bool", "", "NRAS RIM"),
    f("x-nvidia-gpu-vbios-rim-fetched", "bool", "", "NRAS RIM"),
    f("x-nvidia-gpu-vbios-rim-measurements-available", "bool", "", "NRAS RIM"),
    f("x-nvidia-gpu-vbios-rim-schema-validated", "bool", "", "NRAS RIM"),
    f("x-nvidia-gpu-vbios-rim-signature-verified", "bool", "", "NRAS RIM"),
    f("x-nvidia-gpu-vbios-rim-version-match", "bool", "", "NRAS RIM"),
    f("x-nvidia-overall-att-result", "string", "", "NRAS report"),
    f("x-nvidia-gpu-switch-pdis", "list", "", "NRAS topology", {
      member: "string",
    }),
  ]);

  const switchNras = [
    f('["x-nvidia-switch-attestation-report-cert-chain"]["x-nvidia-cert-ocsp-status"]', "string", "", "NRAS certificate", {
      suggestions: ["good"],
    }),
    f('["x-nvidia-switch-attestation-report-cert-chain"]["x-nvidia-cert-status"]', "string", "", "NRAS certificate", {
      suggestions: ["valid"],
    }),
    f("x-nvidia-switch-attestation-report-cert-chain-fwid-match", "bool", "", "NRAS report"),
    f("x-nvidia-switch-attestation-report-parsed", "bool", "", "NRAS report"),
    f("x-nvidia-switch-attestation-report-signature-verified", "bool", "", "NRAS report"),
    f("x-nvidia-switch-arch-check", "bool", "", "NRAS report"),
    f("x-nvidia-switch-attestation-report-nonce-match", "bool", "", "NRAS report"),
    f("secboot", "bool", "", "NRAS configuration"),
    f("dbgstat", "string", "", "NRAS configuration", {
      suggestions: ["disabled"],
    }),
    f("x-nvidia-switch-bios-version", "string", "", "NRAS configuration"),
    f("measres", "string", "", "NRAS measurement", {
      suggestions: ["success"],
    }),
    f('["x-nvidia-switch-bios-rim-cert-chain"]["x-nvidia-cert-ocsp-status"]', "string", "", "NRAS RIM", {
      suggestions: ["good"],
    }),
    f('["x-nvidia-switch-bios-rim-cert-chain"]["x-nvidia-cert-status"]', "string", "", "NRAS RIM", {
      suggestions: ["valid"],
    }),
    f("x-nvidia-switch-bios-rim-fetched", "bool", "", "NRAS RIM"),
    f("x-nvidia-switch-bios-rim-measurements-available", "bool", "", "NRAS RIM"),
    f("x-nvidia-switch-bios-rim-schema-validated", "bool", "", "NRAS RIM"),
    f("x-nvidia-switch-bios-rim-signature-verified", "bool", "", "NRAS RIM"),
    f("x-nvidia-switch-bios-rim-version-match", "bool", "", "NRAS RIM"),
    f("x-nvidia-switch-pdi", "string", "", "NRAS topology"),
    f("x-nvidia-switch-gpu-pdis", "list", "", "NRAS topology", { member: "string" }),
  ];

  const devices = [
    {
      id: "tdx",
      label: "Intel TDX",
      group: "VM",
      inputKey: "tdx",
      note: "",
      ownFields: tdxFields,
    },
    {
      id: "snp",
      label: "AMD SEV-SNP",
      group: "VM",
      inputKey: "snp",
      note: "",
      ownFields: snpFields,
    },
    {
      id: "sgx",
      label: "Intel SGX",
      group: "VM",
      inputKey: "sgx",
      note: "",
      ownFields: sgxFields,
    },
    {
      id: "cca",
      label: "Arm CCA",
      group: "VM",
      inputKey: "cca",
      note: "",
      ownFields: ccaFields,
    },
    {
      id: "csv",
      label: "Hygon CSV",
      group: "VM",
      inputKey: "csv",
      note: "",
      ownFields: csvFields,
    },
    {
      id: "se",
      label: "IBM Secure Execution",
      group: "VM",
      inputKey: "se",
      note: "",
      ownFields: seFields,
    },
    {
      id: "tpm",
      label: "TPM",
      group: "VM",
      inputKey: "tpm",
      note: "",
      ownFields: tpmFields,
    },
    {
      id: "az-tdx-vtpm",
      label: "Azure TDX vTPM",
      group: "Cloud",
      inputKey: "az-tdx-vtpm",
      note: "",
      inherit: ["tdx"],
      ownFields: pcrFields("tpm").concat([
        f("uefi_event_logs", "list", "", "Event log", {
          nested: true,
          nestFields: UEFI_NESTS,
        }),
      ]),
    },
    {
      id: "az-snp-vtpm",
      label: "Azure SNP vTPM",
      group: "Cloud",
      inputKey: "az-snp-vtpm",
      note: "",
      inherit: ["snp"],
      ownFields: pcrFields("tpm").concat([
        f("uefi_event_logs", "list", "", "Event log", {
          nested: true,
          nestFields: UEFI_NESTS,
        }),
      ]),
    },
    {
      id: "nvidia-gpu",
      label: "NVIDIA GPU",
      group: "Accelerator",
      inputKey: "nvidia",
      note: "",
      ownFields: gpuNras,
    },
    {
      id: "nvidia-switch",
      label: "NVIDIA Switch",
      group: "Accelerator",
      inputKey: "nvidia",
      note: "",
      ownFields: switchNras,
    },
    {
      id: "nvidia-ppcie",
      label: "NVIDIA PPCIE",
      group: "Accelerator",
      inputKey: "nvidia",
      note: "",
      ownFields: [
        f("switch_count", "number", "", "Topology"),
        f("gpu_count", "number", "", "Topology"),
      ],
    },
    {
      id: "nvidia-dpu",
      label: "NVIDIA DPU",
      group: "Accelerator",
      inputKey: "nvidia-dpu",
      note: "",
      ownFields: [
        f("device_serial", "string", "", "DICE"),
        f("device_class", "string", "", "DICE"),
        f("firmware_layers_count", "number", "", "DICE"),
        f("accumulated_fwid", "hex", "", "DICE"),
        f("alias_timestamp", "number", "", "DICE"),
        f("session_nonce", "hex", "", "DICE"),
      ],
    },
    {
      id: "hygondcu",
      label: "Hygon DCU",
      group: "Accelerator",
      inputKey: "hygondcu",
      note: "",
      ownFields: [
        f("body.version", "number", "", "Report"),
        f("body.chip_id", "hex", "", "Report"),
        f("body.user_data", "hex", "", "Report"),
        f("body.measure", "hex", "", "Report"),
        f("body.reserved", "hex", "", "Report"),
        f("body.sig_usage", "hex", "", "Report"),
        f("body.sig_algo", "hex", "", "Report"),
      ],
    },
    {
      id: "sample",
      label: "Sample",
      group: "Test",
      inputKey: "sample",
      testOnly: true,
      note: "",
      ownFields: [
        f("svn", "string", "", "Sample"),
        f("launch_digest", "string", "", "Sample", {
          suggestions: ["abcde"],
          labels: { abcde: "Sample digest" },
        }),
        f("platform_version.major", "number", "", "Sample", {
          suggestions: ["1"],
        }),
        f("platform_version.minor", "number", "", "Sample", {
          suggestions: ["4"],
        }),
        f("debug", "bool", "", "Sample"),
      ],
    },
    {
      id: "sampledevice",
      label: "Sample device",
      group: "Test",
      inputKey: "sampledevice",
      testOnly: true,
      note: "",
      ownFields: [f("svn", "string", "", "Sample")],
    },
  ];

  const sharedFields = [
    f(
      "report_data",
      "string",
      "",
      "Shared",
    ),
    f(
      "init_data",
      "string",
      "",
      "Shared",
    ),
    f("init_data_claims", "object", "", "Shared", { nested: true }),
    f("runtime_data_claims", "object", "", "Shared", { nested: true }),
  ];

  const claims = [
    {
      id: "hardware",
      key: "hardware",
      variable: "hardware",
      fallback: 97,
      blurb: "",
    },
    {
      id: "executables",
      key: "executables",
      variable: "executables",
      fallback: 33,
      blurb: "",
    },
    {
      id: "configuration",
      key: "configuration",
      variable: "configuration",
      fallback: 36,
      blurb: "",
    },
    {
      id: "file-system",
      key: "file-system",
      variable: "file_system",
      fallback: 0,
      blurb: "",
    },
    {
      id: "instance-identity",
      key: "instance-identity",
      variable: "instance_identity",
      fallback: 0,
      blurb: "",
    },
    {
      id: "runtime-opaque",
      key: "runtime-opaque",
      variable: "runtime_opaque",
      fallback: 0,
      blurb: "",
    },
    {
      id: "storage-opaque",
      key: "storage-opaque",
      variable: "storage_opaque",
      fallback: 0,
      blurb: "",
    },
    {
      id: "sourced-data",
      key: "sourced-data",
      variable: "sourced_data",
      fallback: 0,
      blurb: "",
    },
  ];

  const scores = [
    { value: 2, label: "2 affirming", comment: "Affirming." },
    { value: 3, label: "3 affirming", comment: "Affirming." },
    { value: 4, label: "4 affirming", comment: "Affirming." },
    { value: 0, label: "0 none", comment: "No assertion." },
    { value: 33, label: "33 warning", comment: "Warning." },
    { value: 36, label: "36 warning", comment: "Warning." },
    { value: 97, label: "97 contraindicated", comment: "Contraindicated." },
  ];

  const byId = {};
  devices.forEach(function (device) {
    byId[device.id] = device;
  });

  function flatten(id, stack) {
    const device = byId[id];
    if (!device) throw new Error("unknown device " + id);
    if (device.fields) return device.fields;
    if (stack.indexOf(id) !== -1) throw new Error("device inherit cycle at " + id);
    const inherited = (device.inherit || []).flatMap(function (parent) {
      return flatten(parent, stack.concat(id));
    });
    const map = new Map();
    inherited.concat(device.ownFields || []).forEach(function (field) {
      map.set(field.path, field);
    });
    device.fields = Array.from(map.values());
    return device.fields;
  }

  devices.forEach(function (device) {
    flatten(device.id, []);
    delete device.ownFields;
  });

  root.AS_CATALOG = {
    devices: devices,
    sharedFields: sharedFields,
    claims: claims,
    scores: scores,
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
