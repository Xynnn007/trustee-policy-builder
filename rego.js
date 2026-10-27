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
        if (text.slice(i, i + 3) === "[_]") {
          segments.push({ wild: true });
          i += 3;
        } else {
          const indexMatch = /^\[(0|[1-9]\d*)\]/.exec(text.slice(i));
          if (indexMatch) {
            segments.push({ index: Number(indexMatch[1]) });
            i += indexMatch[0].length;
          } else {
            const match = /^\[\"((?:\\.|[^\"\\])*)\"\]/.exec(text.slice(i));
            if (!match) return null;
            const segment = match[1].replace(/\\"/g, '"').replace(/\\\\/g, "\\");
            if (!segment) return null;
            segments.push(segment);
            i += match[0].length;
          }
        }
      } else {
        const match = /^[A-Za-z0-9_-]+/.exec(text.slice(i));
        if (!match) return null;
        segments.push(match[0]);
        i += match[0].length;
      }
      if (i < text.length && text[i] !== "." && text[i] !== "[") return null;
    }
    if (!segments.length) return null;
    if (typeof segments[0] !== "string" || !/^[A-Za-z_]/.test(segments[0])) return null;
    return segments;
  }

  function appendPath(base, segments) {
    return segments.reduce(function (expr, segment) {
      if (segment && segment.wild) return expr + "[_]";
      if (segment && typeof segment.index === "number") return expr + "[" + segment.index + "]";
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

  function expandClauses(condition) {
    return [condition].concat(condition.also || []);
  }

  function fieldByPath(device, source, path) {
    const list = source === "shared" ? catalog().sharedFields : device && device.fields;
    if (!list) return null;
    return list.find(function (field) {
      return field.path === path;
    }) || null;
  }

  function compareLeaf(left, nest) {
    if ((nest.rhs || "literal") === "reference") {
      const right = referenceToken(nest.refId);
      if (!right) return { error: "invalid reference key" };
      return { line: left + " in " + right };
    }
    if (nest.literalType === "bool" && Array.isArray(nest.choices) && nest.choices.length) {
      const picked = ["true", "false"].filter(function (value) {
        return nest.choices.indexOf(value) !== -1;
      });
      if (picked.length !== 1) return { error: "pick either true or false" };
      return { line: left + " == " + picked[0] };
    }
    if (String(nest.literal == null ? "" : nest.literal).trim() === "") {
      return { error: "pick a value" };
    }
    const right = literalToken(nest.literalType || "string", nest.literal);
    if (right == null) return { error: "value does not match the field type" };
    return { line: left + " == " + right };
  }

  function nestedLines(device, condition, index) {
    const field = fieldByPath(device, condition.source, condition.path);
    if (!field || !field.nested) return { error: "field does not take nested JSON" };
    const base = parsePath(condition.path);
    if (!base) return { error: "invalid field" };
    const nests = Array.isArray(condition.nests) ? condition.nests : [];
    const root = fieldExpr(device, condition.source, base);
    if (!nests.length) return { lines: [root] };
    const lines = [];
    let expr = root;
    if (field.type === "list") {
      expr = "ev" + String(index == null ? 0 : index);
      lines.push(expr + " := " + root + "[_]");
    }
    for (let i = 0; i < nests.length; i++) {
      const nest = nests[i] || {};
      const text = String(nest.path || "").trim();
      if (!text) return { error: "enter a JSON field path" };
      const segments = parsePath(text);
      if (!segments) return { error: text + " is not a valid JSON field" };
      const rendered = compareLeaf(appendPath(expr, segments), nest);
      if (rendered.error) return { error: text + ": " + rendered.error };
      lines.push(rendered.line);
    }
    return { lines: lines };
  }

  function conditionLine(device, condition, index) {
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

    if (condition.pathMode === "nested") return nestedLines(device, condition, index);

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
    const line = left + " " + op + " " + right;
    const field = fieldByPath(device, condition.source, condition.path);
    const values = op === "in" ? splitList(condition.literal) : [String(condition.literal).trim()];
    return noted(field, values, line);
  }

  function noted(field, values, line) {
    const labels = field && field.labels;
    if (!labels) return { lines: [line] };
    const notes = values
      .map(function (value) {
        return labels[value] ? labels[value] + " (" + value + ")" : "";
      })
      .filter(Boolean);
    if (!notes.length) return { lines: [line] };
    return { lines: ["# " + notes.join(", "), line] };
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
      let seq = 0;
      (rule.conditions || []).forEach(function (condition, index) {
        expandClauses(condition).forEach(function (clause) {
          const slot = seq;
          seq += 1;
          if (clause.kind !== "custom" && clause.pathMode !== "custom" && clause.path) {
            const list = clause.source === "shared" ? catalog().sharedFields : device.fields;
            const known = list.some(function (field) {
              return field.path === clause.path;
            });
            if (!known) {
              issues.push("field " + (index + 1) + ": " + clause.path + " is not in the catalog");
              return;
            }
          }
          const rendered = conditionLine(device, clause, slot);
          if (rendered.error) issues.push("field " + (index + 1) + ": " + rendered.error);
        });
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
      let started = false;
      let lastScore = null;
      rules.forEach(function (rule) {
        const device = deviceById(rule.device);
        const groups = rule.conditions && rule.conditions.length ? rule.conditions : [null];
        groups.forEach(function (condition) {
          const body = ["\t# " + device.id, "\t" + inputPrefix(device)];
          if (condition) {
            let seq = 0;
            expandClauses(condition).forEach(function (clause) {
              conditionLine(device, clause, seq).lines.forEach(function (line) {
                body.push("\t" + line);
              });
              seq += 1;
            });
          }
          const score = Number(rule.score);
          if (!started) {
            lines.push(claim.variable + " := " + score + " if {");
            started = true;
          } else if (score === lastScore) {
            lines.push("}");
            lines.push("");
            lines.push(claim.variable + " := " + score + " if {");
          } else {
            lines.push("} else := " + score + " if {");
          }
          lastScore = score;
          lines.push(body.join("\n"));
        });
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
