// Copyright (c) 2026 Confidential Containers Authors
// SPDX-License-Identifier: Apache-2.0
//
// Turn a Plan B policy description into a Rego file.
// One file is one submodule. `devices` selects which results run it.
// `submod` is the token entry name.

(function (root) {
  "use strict";

  const NAME_RE = /^[A-Za-z_][A-Za-z0-9_-]*$/;
  const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
  const REF_RE = /^[A-Za-z0-9_.:/-]+$/;

  const OPS = {
    "==": "equals",
    "!=": "not equals",
    ">": "greater than",
    ">=": "greater or equal",
    "<": "less than",
    "<=": "less or equal",
    in: "in",
    contains: "contains",
    truthy: "true",
    falsy: "false",
  };

  function opsFor(type) {
    if (type === "bool") return ["==", "!=", "truthy", "falsy"];
    if (type === "number") return ["==", "!=", ">", ">=", "<", "<=", "in"];
    if (type === "list") return ["contains", "truthy"];
    if (type === "object") return ["truthy"];
    return ["==", "!=", ">", ">=", "<", "<=", "in", "contains", "truthy", "falsy"];
  }

  function regoString(value) {
    return (
      '"' +
      String(value)
        .replace(/\\/g, "\\\\")
        .replace(/"/g, '\\"')
        .replace(/\r/g, "\\r")
        .replace(/\n/g, "\\n")
        .replace(/\t/g, "\\t") +
      '"'
    );
  }

  function parsePath(path) {
    const text = String(path || "").trim();
    if (!text) return null;
    const segments = [];
    let i = 0;
    while (i < text.length) {
      if (text[i] === ".") {
        if (segments.length === 0) return null;
        i += 1;
        if (i >= text.length) return null;
      }
      if (text[i] === "[") {
        const match = /^\[\"((?:\\.|[^\"\\])*)\"\]/.exec(text.slice(i));
        if (!match) return null;
        const segment = match[1].replace(/\\"/g, '"').replace(/\\\\/g, "\\");
        if (!segment) return null;
        segments.push(segment);
        i += match[0].length;
      } else {
        const match = /^[A-Za-z0-9_-]+/.exec(text.slice(i));
        if (!match) return null;
        segments.push(match[0]);
        i += match[0].length;
      }
      if (i < text.length && text[i] !== "." && text[i] !== "[") return null;
    }
    if (!segments.length) return null;
    if (!/^[A-Za-z_]/.test(segments[0])) return null;
    return segments;
  }

  function appendPath(base, segments) {
    return segments.reduce(function (expr, segment) {
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(segment)) return expr + "." + segment;
      return expr + "[" + regoString(segment) + "]";
    }, base);
  }

  function catalog() {
    return root.AS_CATALOG;
  }

  function deviceById(id) {
    return catalog().devices.find(function (device) {
      return device.id === id;
    });
  }

  function claimById(id) {
    return catalog().claims.find(function (claim) {
      return claim.id === id;
    });
  }

  function inputPrefix(device) {
    if (IDENT_RE.test(device.inputKey)) return "input." + device.inputKey;
    return "input[" + regoString(device.inputKey) + "]";
  }

  function fieldExpr(device, source, segments) {
    if (source === "shared") return appendPath("input", segments);
    return appendPath(inputPrefix(device), segments);
  }

  function literalToken(type, raw) {
    const text = String(raw == null ? "" : raw).trim();
    if (type === "bool") {
      if (text !== "true" && text !== "false") return null;
      return text;
    }
    if (type === "number") {
      if (!/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/.test(text)) return null;
      return text;
    }
    return regoString(text);
  }

  function referenceToken(id) {
    const text = String(id || "").trim();
    if (!REF_RE.test(text)) return null;
    return "query_reference_value(" + regoString(text) + ")";
  }

  function splitList(raw) {
    return String(raw || "")
      .split(",")
      .map(function (part) {
        return part.trim();
      })
      .filter(function (part) {
        return part.length > 0;
      });
  }

  function conditionLine(device, condition) {
    if (condition.kind === "custom") {
      const lines = String(condition.text || "")
        .split(/\r?\n/)
        .map(function (line) {
          return line.trim();
        })
        .filter(Boolean);
      if (!lines.length) return { error: "empty expression" };
      if (
        lines.some(function (line) {
          return /[{}`]/.test(line);
        })
      ) {
        return { error: "expression cannot contain braces" };
      }
      return { lines: lines };
    }

    const segments = parsePath(condition.path);
    if (!segments) return { error: "invalid field" };
    const left = fieldExpr(device, condition.source, segments);
    const op = condition.op;
    if (!OPS[op]) return { error: "invalid operator" };
    if (op === "truthy") return { lines: [left] };
    if (op === "falsy") return { lines: ["not " + left] };

    const rhsKind = condition.rhs || "literal";
    let right;
    if (rhsKind === "reference") {
      right = referenceToken(condition.refId);
      if (!right) return { error: "invalid reference key" };
    } else if (op === "in") {
      const parts = splitList(condition.literal);
      if (!parts.length) return { error: "pick a value" };
      const rendered = parts.map(function (part) {
        return literalToken(condition.literalType || "string", part);
      });
      if (rendered.some(function (part) { return part == null; })) {
        return { error: "value does not match the field type" };
      }
      right = "{" + rendered.join(", ") + "}";
    } else {
      if (String(condition.literal == null ? "" : condition.literal).trim() === "") {
        return { error: "pick a value" };
      }
      right = literalToken(condition.literalType || "string", condition.literal);
      if (right == null) return { error: "value does not match the field type" };
    }

    if (op === "contains") return { lines: [right + " in " + left] };
    return { lines: [left + " " + op + " " + right] };
  }

  function ruleIssues(policy, rule) {
    const issues = [];
    const claim = claimById(rule.claim);
    const device = deviceById(rule.device);
    if (!claim) issues.push("unknown trust claim");
    if (!device) issues.push("unknown TEE");
    else if ((policy.devices || []).indexOf(device.id) === -1) {
      issues.push(device.id + " is not selected");
    }
    if (rule.score === "" || rule.score == null) {
      issues.push("missing score");
    } else {
      const score = Number(rule.score);
      if (!Number.isInteger(score) || score < -127 || score > 127) {
        issues.push("score must be an integer from -127 to 127");
      }
    }
    if (device && claim) {
      (rule.conditions || []).forEach(function (condition, index) {
        if (condition.kind !== "custom" && condition.pathMode !== "custom" && condition.path) {
          const list = condition.source === "shared" ? catalog().sharedFields : device.fields;
          const known = list.some(function (field) {
            return field.path === condition.path;
          });
          if (!known) {
            issues.push("field " + (index + 1) + " is not in the catalog: " + condition.path);
            return;
          }
        }
        const rendered = conditionLine(device, condition);
        if (rendered.error) issues.push("field " + (index + 1) + ": " + rendered.error);
      });
    }
    return issues;
  }

  function integerOr(value, fallback) {
    const score = Number(value);
    if (Number.isInteger(score) && score >= -127 && score <= 127) return score;
    return fallback;
  }

  function generatePolicy(policy) {
    const errors = [];
    const warnings = [];
    const policyId = String(policy.policyId || "").trim();
    const submod = String(policy.submod || "").trim();
    if (!NAME_RE.test(policyId)) errors.push("Policy id must start with a letter or underscore.");
    if (!NAME_RE.test(submod)) errors.push("Submod must start with a letter or underscore.");

    const selected = catalog().devices.filter(function (device) {
      return (policy.devices || []).indexOf(device.id) !== -1;
    });
    if (!selected.length) errors.push("Select a TEE.");

    const inputKeys = {};
    selected.forEach(function (device) {
      (inputKeys[device.inputKey] = inputKeys[device.inputKey] || []).push(device.id);
      if (device.testOnly) warnings.push(device.id + " is a test verifier.");
    });
    Object.keys(inputKeys).forEach(function (key) {
      if (inputKeys[key].length > 1) {
        warnings.push(inputKeys[key].join(", ") + " share one input object with different fields.");
      }
    });

    const usable = [];
    (policy.rules || []).forEach(function (rule, index) {
      const issues = ruleIssues(policy, rule);
      if (issues.length) {
        errors.push("Claim " + (index + 1) + ": " + issues.join("; "));
        return;
      }
      usable.push(rule);
    });

    const byClaim = new Map();
    usable.forEach(function (rule) {
      if (!byClaim.has(rule.claim)) byClaim.set(rule.claim, []);
      byClaim.get(rule.claim).push(rule);
    });

    const lines = [
      "package policy",
      "",
      "import rego.v1",
      "",
      "# policy id: " + (policyId || "unset"),
      "",
      "devices := [" + selected.map(function (device) { return regoString(device.id); }).join(", ") + "]",
      "submod := " + regoString(submod || ""),
      "",
    ];

    const used = catalog().claims.filter(function (claim) {
      return byClaim.has(claim.id);
    });

    used.forEach(function (claim) {
      const score = integerOr(policy.defaults && policy.defaults[claim.id], claim.fallback);
      lines.push("default " + claim.variable + " := " + score);
      lines.push("");
      const rules = byClaim.get(claim.id);
      rules.forEach(function (rule, index) {
        const device = deviceById(rule.device);
        const body = ["\t# " + device.id, "\t" + inputPrefix(device)];
        (rule.conditions || []).forEach(function (condition) {
          conditionLine(device, condition).lines.forEach(function (line) {
            body.push("\t" + line);
          });
        });
        if (index === 0) {
          lines.push(claim.variable + " := " + Number(rule.score) + " if {");
        } else {
          lines.push("} else := " + Number(rule.score) + " if {");
        }
        lines.push(body.join("\n"));
      });
      lines.push("}");
      lines.push("");
    });

    if (used.length) {
      lines.push("trust_claims := {");
      used.forEach(function (claim) {
        lines.push('\t"' + claim.key + '": ' + claim.variable + ",");
      });
      lines.push("}");
      lines.push("");
    } else {
      lines.push("# No claims yet.");
      lines.push("");
    }

    return {
      ok: errors.length === 0 && used.length > 0,
      errors: errors,
      warnings: warnings,
      rego: lines.join("\n"),
    };
  }

  root.AS_REGO = {
    OPS: OPS,
    opsFor: opsFor,
    parsePath: parsePath,
    regoString: regoString,
    generatePolicy: generatePolicy,
    ruleIssues: ruleIssues,
    deviceById: deviceById,
    claimById: claimById,
    inputPrefix: inputPrefix,
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
