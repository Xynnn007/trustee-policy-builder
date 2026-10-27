// Copyright (c) 2026 Confidential Containers Authors
// SPDX-License-Identifier: Apache-2.0

(function (root) {
  "use strict";

  function compare(path, op, literal, literalType) {
    return {
      kind: "compare",
      source: "device",
      pathMode: "catalog",
      path: path,
      op: op,
      rhs: "literal",
      literalType: literalType,
      literal: literal,
      refId: "",
      text: "",
    };
  }

  function reference(path, op, refId) {
    return {
      kind: "compare",
      source: "device",
      pathMode: "catalog",
      path: path,
      op: op,
      rhs: "reference",
      literalType: "string",
      literal: "",
      refId: refId,
      text: "",
    };
  }

  function truthy(path) {
    return compare(path, "truthy", "", "bool");
  }

  function sharedEquals(path, literal) {
    return {
      kind: "compare",
      source: "shared",
      pathMode: "custom",
      path: path,
      op: "==",
      rhs: "literal",
      literalType: "string",
      literal: literal,
      refId: "",
      text: "",
    };
  }

  function rule(claim, score, device, conditions) {
    return { claim: claim, score: score, device: device, conditions: conditions };
  }

  function all(head, rest) {
    if (rest && rest.length) head.also = rest;
    return [head];
  }

  root.AS_PRESETS = [
    {
      id: "blank",
      name: "Blank",
      blurb: "Start from an empty policy.",
      policyId: "policy",
      submod: "submod",
      devices: [],
      defaults: {},
      rules: [],
    },
    {
      id: "rfc-cpu",
      name: "RFC cpu",
      blurb: "One policy for TDX and SNP. TDX debug must be off.",
      policyId: "cpu",
      submod: "cpu",
      devices: ["tdx", "snp"],
      defaults: { hardware: 97 },
      rules: [
        rule("hardware", 2, "tdx", [compare("td_attributes.debug", "==", "false", "bool")]),
        rule("hardware", 2, "snp", []),
      ],
    },
    {
      id: "tdx-measure",
      name: "TDX measurement",
      blurb: "TCB, MR_TD, RTMR, and debug. Measurements come from RVPS.",
      policyId: "tdx",
      submod: "tdx",
      devices: ["tdx"],
      defaults: { hardware: 97, executables: 33, configuration: 36 },
      rules: [
        rule("hardware", 2, "tdx", all(
          compare("quote.header.tee_type", "==", "81000000", "string"),
          [
            compare("tcb_status", "==", "UpToDate", "string"),
            compare("collateral_expiration_status", "==", "0", "string"),
            reference("quote.body.mr_td", "in", "mr_td"),
          ],
        )),
        rule("executables", 3, "tdx", all(
          reference("quote.body.rtmr_1", "in", "rtmr_1"),
          [reference("quote.body.rtmr_2", "in", "rtmr_2")],
        )),
        rule("configuration", 2, "tdx", all(
          compare("td_attributes.debug", "==", "false", "bool"),
          [reference("quote.body.xfam", "in", "xfam")],
        )),
      ],
    },
    {
      id: "nvidia-gpu",
      name: "NVIDIA GPU",
      blurb: "Remote NRAS GPU. VBIOS versions come from RVPS.",
      policyId: "gpu",
      submod: "gpu",
      devices: ["nvidia-gpu"],
      defaults: { hardware: 97, configuration: 36 },
      rules: [
        rule("hardware", 2, "nvidia-gpu", all(
          truthy("x-nvidia-gpu-attestation-report-parsed"),
          [
            truthy("x-nvidia-gpu-attestation-report-signature-verified"),
            truthy("x-nvidia-gpu-arch-check"),
            compare(
              '["x-nvidia-gpu-attestation-report-cert-chain"]["x-nvidia-cert-ocsp-status"]',
              "==",
              "good",
              "string",
            ),
            compare(
              '["x-nvidia-gpu-attestation-report-cert-chain"]["x-nvidia-cert-status"]',
              "==",
              "valid",
              "string",
            ),
          ],
        )),
        rule("configuration", 2, "nvidia-gpu", all(
          truthy("secboot"),
          [
            compare("dbgstat", "==", "disabled", "string"),
            reference("x-nvidia-gpu-vbios-version", "in", "allowed_vbios_versions"),
          ],
        )),
        rule("configuration", 3, "nvidia-gpu", all(
          truthy("secboot"),
          [compare("dbgstat", "==", "disabled", "string")],
        )),
      ],
    },
    {
      id: "runtime",
      name: "Runtime",
      blurb: "Second submodule for TDX or SNP. Checks init_data_claims.runtime.",
      policyId: "runtime",
      submod: "runtime",
      devices: ["tdx", "snp"],
      defaults: { executables: 33 },
      rules: [
        rule("executables", 3, "tdx", [sharedEquals("init_data_claims.runtime", "runtime1")]),
        rule("executables", 3, "snp", [sharedEquals("init_data_claims.runtime", "runtime1")]),
      ],
    },
  ];
})(typeof globalThis !== "undefined" ? globalThis : this);
