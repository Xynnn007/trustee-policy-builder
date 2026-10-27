// Copyright (c) 2026 Confidential Containers Authors
// SPDX-License-Identifier: Apache-2.0

(function (root) {
  "use strict";

  const catalog = root.AS_CATALOG;
  const rego = root.AS_REGO;

  const CLAIM_LABEL = {
    hardware: "Hardware",
    executables: "Boot software",
    configuration: "Configuration",
    "file-system": "File system",
    "instance-identity": "Instance identity",
    "runtime-opaque": "Runtime",
    "storage-opaque": "Storage",
    "sourced-data": "Sourced data",
  };

  const state = { kind: "", policies: [], activeId: "", toast: "" };

  function esc(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function uid() {
    if (root.crypto && root.crypto.randomUUID) return root.crypto.randomUUID();
    return "id-" + Math.random().toString(16).slice(2);
  }

  function active() {
    return state.policies.find(function (policy) {
      return policy.uid === state.activeId;
    }) || state.policies[0];
  }

  function deviceById(id) {
    return rego.deviceById(id);
  }

  function claimById(id) {
    return catalog.claims.find(function (claim) {
      return claim.id === id;
    });
  }

  function claimLabel(id) {
    return CLAIM_LABEL[id] || id;
  }

  function groupClass(name) {
    return "tee-" + String(name || "other").toLowerCase().replace(/[^a-z0-9]+/g, "-");
  }

  function selectedDevices(policy) {
    return catalog.devices.filter(function (device) {
      return policy.devices.indexOf(device.id) !== -1;
    });
  }

  function literalTypeOf(field) {
    if (!field) return "string";
    if (field.type === "bool") return "bool";
    if (field.type === "number") return "number";
    if (field.type === "list") return field.member || "string";
    return "string";
  }

  function fieldsFor(device, source) {
    if (source === "shared") return catalog.sharedFields;
    return device ? device.fields : [];
  }

  function findField(device, row) {
    if (!row || row.custom) return null;
    return fieldsFor(device, row.source).find(function (field) {
      return field.path === row.path;
    }) || null;
  }

  function closedSet(field) {
    if (!field) return null;
    if (field.type === "bool") return ["true", "false"];
    if (field.suggestions && field.suggestions.length) return field.suggestions.slice();
    return null;
  }

  function blankPolicy() {
    return {
      uid: uid(),
      policyId: "policy",
      submod: "cpu",
      devices: [],
      defaults: {},
      rules: [],
      draft: null,
    };
  }

  function newRow(deviceId) {
    const device = deviceById(deviceId);
    const field = device && device.fields[0];
    return {
      id: uid(),
      source: "device",
      path: field ? field.path : "",
      custom: false,
      choices: [],
      rhs: "literal",
      literal: "",
      refId: "",
      nests: [],
      also: [],
    };
  }

  function blankNest() {
    return {
      path: "",
      custom: false,
      literalType: "string",
      rhs: "literal",
      literal: "",
      refId: "",
      choices: [],
    };
  }

  function nestSpecs(field) {
    return (field && field.nestFields) || [];
  }

  function nestSpec(field, path) {
    return nestSpecs(field).find(function (spec) {
      return spec.path === path;
    }) || null;
  }

  function applyNestSpec(nest, spec) {
    nest.custom = false;
    nest.path = spec.path;
    nest.rhs = "literal";
    nest.refId = "";
    nest.literal = "";
    nest.choices = [];
    nest.literalType =
      spec.type === "bool" ? "bool" : spec.type === "number" ? "number" : "string";
  }

  function clauseAt(policy, target) {
    const row = branchAt(policy).rows[Number(target.dataset.index)];
    if (!row) return null;
    if (target.dataset.clause == null || target.dataset.clause === "") return row;
    return (row.also || [])[Number(target.dataset.clause)] || null;
  }

  function nestAt(policy, target) {
    const row = clauseAt(policy, target);
    if (!row || !row.nests) return null;
    return row.nests[Number(target.dataset.nest)] || null;
  }

  function syncNests(row, device) {
    const field = findField(device, row);
    if (field && field.nested) {
      if (!row.nests) row.nests = [];
      if (!row.nests.length) {
        const nest = blankNest();
        const spec = nestSpecs(field)[0];
        if (spec) applyNestSpec(nest, spec);
        row.nests.push(nest);
      }
      return;
    }
    row.nests = [];
  }

  function newBranch(deviceId) {
    return {
      id: uid(),
      device: deviceId,
      rows: [],
    };
  }

  function splitChoices(literal) {
    return String(literal || "")
      .split(",")
      .map(function (part) {
        return part.trim();
      })
      .filter(Boolean);
  }

  function rowFromCondition(condition, device) {
    const row = {
      id: uid(),
      source: condition.source || "device",
      path: condition.path || "",
      custom: condition.pathMode === "custom",
      choices: [],
      rhs: condition.rhs === "reference" ? "reference" : "literal",
      literal: condition.literal == null ? "" : String(condition.literal),
      refId: condition.refId || "",
      nests: Array.isArray(condition.nests)
        ? condition.nests.map(function (nest) {
            const choices = Array.isArray(nest.choices) ? nest.choices.slice() : [];
            return {
              path: nest.path || "",
              custom: nest.custom === true,
              literalType: nest.literalType || "string",
              rhs: nest.rhs === "reference" ? "reference" : "literal",
              literal: nest.literal == null ? "" : String(nest.literal),
              refId: nest.refId || "",
              choices: choices.length
                ? choices
                : nest.literalType === "bool" && (nest.literal === "true" || nest.literal === "false")
                  ? [String(nest.literal)]
                  : [],
            };
          })
        : [],
    };
    const field = findField(device, row);
    const closed = closedSet(field);
    if (closed && condition.op === "in" && condition.rhs !== "reference") {
      row.choices = splitChoices(condition.literal);
    } else if (closed && condition.op === "==") {
      row.choices = [String(condition.literal)];
    } else if (closed && condition.op === "truthy") {
      row.choices = ["true"];
    } else if (closed && condition.op === "falsy") {
      row.choices = ["false"];
    }
    row.also = Array.isArray(condition.also)
      ? condition.also.map(function (extra) {
          const copy = {};
          Object.keys(extra).forEach(function (key) {
            if (key !== "also") copy[key] = extra[key];
          });
          const child = rowFromCondition(copy, device);
          child.also = [];
          return child;
        })
      : [];
    return row;
  }

  function conditionFromRow(row, device) {
    const condition = buildCondition(row, device);
    if (row.also && row.also.length) {
      condition.also = row.also.map(function (extra) {
        return buildCondition(extra, device);
      });
    }
    return condition;
  }

  function buildCondition(row, device) {
    const field = findField(device, row);
    if (field && field.nested) {
      return {
        kind: "compare",
        source: row.source,
        pathMode: "nested",
        path: field.path,
        text: "",
        refId: "",
        literal: "",
        literalType: "string",
        op: "==",
        rhs: "literal",
        nests: (row.nests || []).map(function (nest) {
          const literalType =
            nest.literalType === "number" || nest.literalType === "bool" ? nest.literalType : "string";
          const choices = Array.isArray(nest.choices) ? nest.choices.slice() : [];
          return {
            path: String(nest.path || "").trim(),
            custom: nest.custom === true,
            rhs: nest.rhs === "reference" ? "reference" : "literal",
            literalType: literalType,
            literal:
              literalType === "bool" && choices.length
                ? choices.join(", ")
                : nest.literal == null
                  ? ""
                  : String(nest.literal),
            refId: nest.refId || "",
            choices: choices,
          };
        }),
      };
    }
    const closed = closedSet(field);
    const condition = {
      kind: "compare",
      source: row.source,
      pathMode: row.custom ? "custom" : "catalog",
      path: row.path,
      text: "",
      refId: row.refId || "",
      literal: "",
      literalType: literalTypeOf(field),
      op: "==",
      rhs: "literal",
    };
    if (closed) {
      const picked = closed.filter(function (value) {
        return row.choices.indexOf(value) !== -1;
      });
      condition.literalType = field.type === "bool" ? "bool" : literalTypeOf(field);
      if (field.type === "bool" || picked.length <= 1) {
        condition.op = "==";
        condition.literal = picked[0] || "";
      } else {
        condition.op = "in";
        condition.literal = picked.join(", ");
      }
      return condition;
    }
    if (row.rhs === "reference") {
      condition.op = "in";
      condition.rhs = "reference";
      condition.literalType = "string";
      return condition;
    }
    condition.literal = row.literal;
    return condition;
  }

  function rulesForClaim(policy, claimId) {
    return policy.rules.filter(function (rule) {
      return rule.claim === claimId;
    });
  }

  function usedClaims(policy) {
    return catalog.claims.filter(function (claim) {
      return policy.rules.some(function (rule) {
        return rule.claim === claim.id;
      });
    });
  }

  function openCheck(policy, claimId) {
    const devices = selectedDevices(policy);
    if (!devices.length) {
      state.toast = "Pick at least one platform first.";
      render();
      return;
    }
    state.toast = "";
    const existing = rulesForClaim(policy, claimId);
    const claim = claimById(claimId);
    const branches = existing.length
      ? existing.map(function (rule) {
          const device = deviceById(rule.device);
          return {
            id: rule.id,
            device: rule.device,
            rows: (rule.conditions || []).map(function (condition) {
              return rowFromCondition(condition, device);
            }),
          };
        })
      : [newBranch(devices[0].id)];
    policy.draft = {
      claim: claimId,
      score: existing[0] ? existing[0].score : 2,
      fallback: policy.defaults[claimId] != null && policy.defaults[claimId] !== ""
        ? Number(policy.defaults[claimId])
        : claim.fallback,
      focus: branches[0].id,
      branches: branches,
      issues: [],
    };
    render();
  }

  function draftToRules(policy) {
    const draft = policy.draft;
    return draft.branches.map(function (branch) {
      const device = deviceById(branch.device);
      return {
        id: branch.id,
        claim: draft.claim,
        score: draft.score,
        device: branch.device,
        conditions: branch.rows.map(function (row) {
          return conditionFromRow(row, device);
        }),
      };
    });
  }

  function saveDraft(policy) {
    const rules = draftToRules(policy);
    const issues = [];
    if (!rules.length) issues.push("Add a platform under this check.");
    const seen = {};
    rules.forEach(function (rule, index) {
      if (seen[rule.device]) issues.push(rule.device + " is listed twice.");
      seen[rule.device] = true;
      if (policy.devices.indexOf(rule.device) === -1) {
        issues.push(rule.device + " is not selected on the policy.");
      }
      rego.ruleIssues(policy, rule).forEach(function (issue) {
        issues.push("Platform " + (index + 1) + ": " + issue);
      });
    });
    if (issues.length) {
      policy.draft.issues = issues;
      render();
      return;
    }
    policy.defaults[policy.draft.claim] = policy.draft.fallback;
    policy.rules = policy.rules
      .filter(function (rule) {
        return rule.claim !== policy.draft.claim;
      })
      .concat(rules);
    policy.draft = null;
    state.toast = "";
    render();
  }

  function fieldOf(condition, device) {
    const list = condition && condition.source === "shared" ? catalog.sharedFields : device && device.fields;
    if (!list) return null;
    return list.find(function (field) {
      return field.path === condition.path;
    }) || null;
  }

  function showValue(field, value) {
    if (field && field.labels && field.labels[value]) return field.labels[value];
    return value;
  }

  function requirementLines(condition, device) {
    return [summarizeClause(condition, device)].concat(
      (condition.also || []).map(function (extra) {
        return summarizeClause(extra, device);
      }),
    );
  }

  function summarizeClause(condition, device) {
    const field = fieldOf(condition, device);
    if (condition.pathMode === "nested") {
      const nests = condition.nests || [];
      if (!nests.length) return condition.path + " present";
      return nests
        .map(function (nest) {
          const value = nest.rhs === "reference" ? "from RVPS " + nest.refId : showValue(null, nest.literal);
          return condition.path + "." + nest.path + " = " + value;
        })
        .join(" · ");
    }
    if (!condition.path) return "present";
    if (condition.rhs === "reference") return condition.path + " from RVPS";
    if (condition.op === "in") {
      return condition.path + " ∈ {" + splitChoices(condition.literal).map(function (value) {
        return showValue(field, value);
      }).join(", ") + "}";
    }
    if (condition.op === "==") return condition.path + " = " + showValue(field, condition.literal);
    return condition.path;
  }

  function fieldOptions(fields, selected, custom) {
    let html = "";
    let group = null;
    fields.forEach(function (field) {
      if (field.group !== group) {
        if (group !== null) html += "</optgroup>";
        group = field.group;
        html += '<optgroup label="' + esc(group) + '">';
      }
      html +=
        '<option value="' +
        esc(field.path) +
        '"' +
        (field.path === selected && !custom ? " selected" : "") +
        ">" +
        esc(field.path) +
        (field.nested ? " (JSON)" : "") +
        "</option>";
    });
    if (group !== null) html += "</optgroup>";
    html +=
      '<option value="__custom__"' + (custom ? " selected" : "") + ">Custom path</option>";
    return html;
  }

  function choiceLabel(field, value) {
    const label = field && field.labels && field.labels[value];
    if (!label || label === value) return esc(value);
    return '<span class="choice-name" title="' + esc(value) + '">' + esc(label) + "</span>";
  }

  function choiceBoxes(row, index, values, field) {
    const exclusive = field && field.type === "bool";
    return (
      '<div class="choices">' +
      values
        .map(function (value) {
          const on = row.choices.indexOf(value) !== -1;
          return (
            '<label class="choice"><input type="checkbox" data-action="toggle-choice" data-index="' +
            index +
            '"' +
            (exclusive ? ' data-exclusive="true"' : "") +
            ' data-value="' +
            esc(value) +
            '"' +
            (on ? " checked" : "") +
            ">" +
            choiceLabel(field, value) +
            "</label>"
          );
        })
        .join("") +
      "</div>"
    );
  }

  function branchAt(policy) {
    const draft = policy.draft;
    return draft.branches.find(function (branch) {
      return branch.id === draft.focus;
    }) || draft.branches[0];
  }

  function nestChoiceBoxes(nest, index, nestIndex, values) {
    const picked = nest.choices || [];
    return (
      '<div class="choices">' +
      values
        .map(function (value) {
          const on = picked.indexOf(value) !== -1;
          return (
            '<label class="choice"><input type="checkbox" data-action="toggle-nest-choice" data-exclusive="true" data-index="' +
            index +
            '" data-nest="' +
            nestIndex +
            '" data-value="' +
            esc(value) +
            '"' +
            (on ? " checked" : "") +
            ">" +
            esc(value) +
            "</label>"
          );
        })
        .join("") +
      "</div>"
    );
  }

  function nestEnumSelect(nest, index, nestIndex, values) {
    const options = values.slice();
    if (nest.literal && options.indexOf(nest.literal) === -1) options.unshift(nest.literal);
    return (
      '<select data-model="nest-literal" data-index="' +
      index +
      '" data-nest="' +
      nestIndex +
      '"><option value="">Choose</option>' +
      options
        .map(function (value) {
          return (
            '<option value="' +
            esc(value) +
            '"' +
            (nest.literal === value ? " selected" : "") +
            ">" +
            esc(value) +
            "</option>"
          );
        })
        .join("") +
      "</select>"
    );
  }

  function nestPathControl(nest, index, nestIndex, field) {
    const specs = nestSpecs(field);
    if (!specs.length) {
      return (
        '<input data-model="nest-path" data-index="' +
        index +
        '" data-nest="' +
        nestIndex +
        '" value="' +
        esc(nest.path) +
        '" placeholder="runtime or nested.key" spellcheck="false">'
      );
    }
    const known = !nest.custom && !!nestSpec(field, nest.path);
    const custom = !known;
    return (
      '<select data-model="nest-path" data-index="' +
      index +
      '" data-nest="' +
      nestIndex +
      '" data-redraw="true"><option value=""' +
      (!nest.path && !nest.custom ? " selected" : "") +
      ">Choose a field</option>" +
      specs
        .map(function (spec) {
          return (
            '<option value="' +
            esc(spec.path) +
            '"' +
            (known && nest.path === spec.path ? " selected" : "") +
            ">" +
            esc(spec.path) +
            "</option>"
          );
        })
        .join("") +
      '<option value="__custom__"' +
      (custom && (nest.custom || nest.path) ? " selected" : "") +
      ">Custom path</option></select>" +
      (custom && (nest.custom || nest.path)
        ? '<input data-model="nest-pathtext" data-index="' +
          index +
          '" data-nest="' +
          nestIndex +
          '" value="' +
          esc(nest.custom || !nestSpec(field, nest.path) ? nest.path : "") +
          '" placeholder="details.data.content.name" spellcheck="false">'
        : "")
    );
  }

  function nestValueControl(nest, index, nestIndex, spec) {
    if (spec && spec.type === "bool") {
      return (
        '<div class="expect-box"><span class="expect-label">Must be</span>' +
        nestChoiceBoxes(nest, index, nestIndex, ["true", "false"]) +
        "</div>"
      );
    }
    if (spec && spec.suggestions && spec.suggestions.length) {
      return (
        '<label class="field">Value' +
        nestEnumSelect(nest, index, nestIndex, spec.suggestions) +
        "</label>"
      );
    }
    const type = nest.literalType === "number" || nest.literalType === "bool" ? nest.literalType : "string";
    const typed =
      nest.rhs === "reference"
        ? '<input data-model="nest-ref" data-index="' +
          index +
          '" data-nest="' +
          nestIndex +
          '" value="' +
          esc(nest.refId) +
          '" placeholder="reference name" spellcheck="false">'
        : type === "bool"
          ? nestChoiceBoxes(nest, index, nestIndex, ["true", "false"])
          : '<input data-model="nest-literal" data-index="' +
            index +
            '" data-nest="' +
            nestIndex +
            '" value="' +
            esc(nest.literal) +
            '" placeholder="' +
            (type === "number" ? "0" : "value") +
            '" spellcheck="false">';
    const typeSelect = spec
      ? ""
      : '<label class="field">Type<select data-model="nest-type" data-index="' +
        index +
        '" data-nest="' +
        nestIndex +
        '" data-redraw="true"><option value="string"' +
        (type === "string" ? " selected" : "") +
        '>string</option><option value="number"' +
        (type === "number" ? " selected" : "") +
        '>number</option><option value="bool"' +
        (type === "bool" ? " selected" : "") +
        ">bool</option></select></label>";
    return (
      typeSelect +
      '<div class="nest-value"><div class="seg expect">' +
      '<button type="button" class="btn' +
      (nest.rhs !== "reference" ? " primary" : "") +
      '" data-action="nest-rhs" data-index="' +
      index +
      '" data-nest="' +
      nestIndex +
      '" data-value="literal">Fixed value</button>' +
      '<button type="button" class="btn' +
      (nest.rhs === "reference" ? " primary" : "") +
      '" data-action="nest-rhs" data-index="' +
      index +
      '" data-nest="' +
      nestIndex +
      '" data-value="reference">RVPS</button></div>' +
      typed +
      "</div>"
    );
  }

  function nestEditor(row, index, field, idSuffix) {
    const nests = row.nests || [];
    const known = nestSpecs(field).length > 0;
    const hint = known
      ? "Pick a known field. Use Custom path only for a JSON key that is not listed. Fields here match the same list item."
      : "Add any field inside this JSON value. Dots go deeper. [_] picks a list item.";
    const cards = nests
      .map(function (nest, nestIndex) {
        const spec = nest.custom ? null : nestSpec(field, nest.path);
        const showType = !spec;
        return (
          '<div class="nest" id="nest-' +
          index +
          "-" +
          (idSuffix || "m") +
          "-" +
          nestIndex +
          '"><div class="nest-top"><span class="row-kicker">JSON field ' +
          (nestIndex + 1) +
          '</span><button type="button" class="btn danger" data-action="delete-nest" data-index="' +
          index +
          '" data-nest="' +
          nestIndex +
          '">Remove</button></div><div class="nest-grid' +
          (showType ? "" : " is-single") +
          '"><label class="field">Field' +
          nestPathControl(nest, index, nestIndex, field) +
          "</label>" +
          nestValueControl(nest, index, nestIndex, spec) +
          "</div></div>"
        );
      })
      .join("");
    return (
      '<div class="nests"><span class="expect-label">JSON fields</span><p class="nest-hint">' +
      esc(hint) +
      "</p>" +
      cards +
      '<button type="button" class="btn add" data-action="add-nest" data-index="' +
      index +
      '">Add JSON field</button></div>'
    );
  }

  function clauseBody(policy, row, index, idSuffix) {
    const device = deviceById(branchAt(policy).device);
    const fields = fieldsFor(device, row.source);
    const field = findField(device, row);
    const closed = closedSet(field);
    const nested = field && field.nested && !row.custom;
    let value = "";
    if (nested) value = nestEditor(row, index, field, idSuffix || "m");
    else if (closed) value = choiceBoxes(row, index, closed, field);
    else {
      value =
        '<div class="seg expect">' +
        '<button type="button" class="btn' +
        (row.rhs !== "reference" ? " primary" : "") +
        '" data-action="row-rhs" data-index="' +
        index +
        '" data-value="literal">Fixed value</button>' +
        '<button type="button" class="btn' +
        (row.rhs === "reference" ? " primary" : "") +
        '" data-action="row-rhs" data-index="' +
        index +
        '" data-value="reference">RVPS</button></div>';
      value +=
        row.rhs === "reference"
          ? '<input data-model="row-ref" data-index="' +
            index +
            '" value="' +
            esc(row.refId) +
            '" placeholder="reference name" spellcheck="false">'
          : '<input data-model="row-literal" data-index="' +
            index +
            '" value="' +
            esc(row.literal) +
            '" placeholder="type a value" spellcheck="false">';
    }
    const expect = nested
      ? value
      : closed
        ? '<div class="expect-box"><span class="expect-label">Must be</span>' + value + "</div>"
        : '<div class="expect-box' +
          (row.rhs === "reference" ? " is-ref" : "") +
          '"><span class="expect-label">Must match</span>' +
          value +
          "</div>";
    const custom =
      row.custom
        ? '<input data-model="row-pathtext" data-index="' +
          index +
          '" value="' +
          esc(row.path) +
          '" placeholder="quote.body.mr_td" spellcheck="false">'
        : "";
    return (
      '<div class="clause"><div class="seg source">' +
      '<button type="button" class="btn' +
      (row.source !== "shared" ? " primary" : "") +
      '" data-action="row-source" data-index="' +
      index +
      '" data-value="device">This platform</button>' +
      '<button type="button" class="btn' +
      (row.source === "shared" ? " primary" : "") +
      '" data-action="row-source" data-index="' +
      index +
      '" data-value="shared">Shared</button></div><div class="row-body' +
      (nested ? " is-nested" : "") +
      '"><label class="field">Evidence field<select data-model="row-path" data-index="' +
      index +
      '" data-redraw="true">' +
      fieldOptions(fields, row.path, row.custom) +
      "</select>" +
      custom +
      "</label>" +
      expect +
      "</div></div>"
    );
  }

  function rowView(policy, row, index) {
    return (
      '<article class="row' +
      (row.source === "shared" ? " is-shared" : " is-device") +
      '"><header class="row-top"><span class="row-kicker">Condition ' +
      (index + 1) +
      '</span><button type="button" class="btn danger" data-action="delete-row" data-index="' +
      index +
      '">Remove</button></header>' +
      clauseBody(policy, row, index, "m") +
      andExtras(policy, row, index) +
      "</article>"
    );
  }

  function tagClause(html, clause) {
    return html.replace(/data-index="(\d+)"/g, 'data-index="$1" data-clause="' + clause + '"');
  }

  function andExtras(policy, row, index) {
    const extras = row.also || [];
    return (
      extras
        .map(function (extra, clause) {
          return (
            '<div class="and-part" id="and-' +
            index +
            "-" +
            clause +
            '"><div class="and-part-top"><span class="row-kicker">Also required</span>' +
            '<button type="button" class="btn danger" data-action="delete-also" data-index="' +
            index +
            '" data-clause="' +
            clause +
            '">Remove</button></div>' +
            tagClause(clauseBody(policy, extra, index, String(clause)), clause) +
            "</div>"
          );
        })
        .join("") +
      '<button type="button" class="btn add and-add" data-action="add-also" data-index="' +
      index +
      '">AND another field</button>'
    );
  }

  function modalView(policy) {
    const draft = policy.draft;
    if (!draft) return "";
    const devices = selectedDevices(policy);
    const branch = branchAt(policy);
    const used = {};
    draft.branches.forEach(function (item) {
      used[item.device] = true;
    });
    const unused = devices.filter(function (device) {
      return !used[device.id];
    });
    return (
      '<div class="modal-back" data-action="close-modal">' +
      '<form class="modal" id="draft">' +
      '<div class="modal-head"><h2>When is ' +
      esc(claimLabel(draft.claim).toLowerCase()) +
      ' trusted?</h2><button type="button" class="btn quiet" data-action="cancel-draft">Close</button></div>' +
      '<p class="lead">Pick a score when the checks pass. Add one section per platform; each can require different fields.</p>' +
      '<div class="pair scores">' +
      '<label class="field score-pass">Pass score<select data-model="draft-score">' +
      catalog.scores
        .map(function (score) {
          return (
            '<option value="' +
            score.value +
            '"' +
            (Number(draft.score) === score.value ? " selected" : "") +
            ">" +
            esc(score.label) +
            "</option>"
          );
        })
        .join("") +
      "</select></label>" +
      '<label class="field score-else">Otherwise<select data-model="draft-fallback">' +
      catalog.scores
        .map(function (score) {
          return (
            '<option value="' +
            score.value +
            '"' +
            (Number(draft.fallback) === score.value ? " selected" : "") +
            ">" +
            esc(score.label) +
            "</option>"
          );
        })
        .join("") +
      "</select></label></div>" +
      '<div class="platform-tabs">' +
      draft.branches
        .map(function (item) {
          const device = deviceById(item.device);
          const on = item.id === draft.focus ? " is-on" : "";
          return (
            '<button type="button" class="tab' +
            on +
            '" data-action="focus-branch" data-id="' +
            esc(item.id) +
            '">' +
            esc(device ? device.label : item.device) +
            "</button>"
          );
        })
        .join("") +
      (unused.length
        ? '<button type="button" class="tab add" data-action="add-branch">+ Platform</button>'
        : "") +
      "</div>" +
      (branch
        ? '<div class="branch">' +
          '<div class="branch-head">' +
          '<label class="field grow">Platform<select data-model="branch-device" data-redraw="true">' +
          devices
            .map(function (device) {
              const taken =
                used[device.id] && device.id !== branch.device ? " disabled" : "";
              return (
                '<option value="' +
                esc(device.id) +
                '"' +
                (branch.device === device.id ? " selected" : "") +
                taken +
                ">" +
                esc(device.label) +
                "</option>"
              );
            })
            .join("") +
          "</select></label>" +
          (draft.branches.length > 1
            ? '<button type="button" class="btn danger" data-action="delete-branch">Remove platform</button>'
            : "") +
          "</div>" +
          '<p class="hint">' +
          (branch.rows.length
            ? "Each condition is its own alternative (OR). AND another field stays inside that condition."
            : "No extra fields. Passing only requires this platform’s evidence. Another platform is a separate alternative (OR).") +
          "</p>" +
          '<div class="logic-or"><p class="logic-label">Any condition</p><div class="rows">' +
          branch.rows
            .map(function (row, index) {
              return (index ? '<p class="match-or">OR</p>' : "") + rowView(policy, row, index);
            })
            .join("") +
          "</div></div>" +
          '<button type="button" class="btn add" data-action="add-row">Add field</button></div>'
        : "") +
      '<div class="bar end">' +
      '<button type="button" class="btn quiet" data-action="cancel-draft">Cancel</button>' +
      '<button type="button" class="btn primary" data-action="save-draft">Save check</button></div>' +
      (draft.issues && draft.issues.length
        ? '<p class="issues">' + esc(draft.issues.join("\n")) + "</p>"
        : "") +
      "</form></div>"
    );
  }

  function teePicker(policy) {
    const groups = [];
    catalog.devices.forEach(function (device) {
      let group = groups.find(function (item) {
        return item.name === device.group;
      });
      if (!group) {
        group = { name: device.group, devices: [] };
        groups.push(group);
      }
      group.devices.push(device);
    });
    return (
      '<div class="groups">' +
      groups
        .map(function (group) {
          return (
            '<section class="tee-group ' +
            groupClass(group.name) +
            '"><h3><span>' +
            esc(group.name) +
            '</span><span class="group-count' +
            (group.devices.some(function (device) {
              return policy.devices.indexOf(device.id) !== -1;
            })
              ? " is-set"
              : "") +
            '">' +
            group.devices.filter(function (device) {
              return policy.devices.indexOf(device.id) !== -1;
            }).length +
            "/" +
            group.devices.length +
            "</span></h3><div class=\"tees\">" +
            group.devices
              .map(function (device) {
                const on = policy.devices.indexOf(device.id) !== -1;
                return (
                  '<label class="tee' +
                  (on ? " is-on" : "") +
                  (device.testOnly ? " is-test" : "") +
                  '"><input type="checkbox" data-model="device" data-device="' +
                  esc(device.id) +
                  '" data-redraw="true"' +
                  (on ? " checked" : "") +
                  "><span>" +
                  esc(device.label) +
                  "</span></label>"
                );
              })
              .join("") +
            "</div></section>"
          );
        })
        .join("") +
      "</div>"
    );
  }

  function checksView(policy) {
    const claims = usedClaims(policy);
    const unused = catalog.claims.filter(function (claim) {
      return !claims.some(function (item) {
        return item.id === claim.id;
      });
    });
    let html = "";
    if (!claims.length) {
      html +=
        '<p class="empty">Nothing scored yet. Start with hardware, boot software, or configuration.</p>';
    } else {
      html +=
        '<div class="checks">' +
        claims
          .map(function (claim) {
            const rules = rulesForClaim(policy, claim.id);
            const fallback =
              policy.defaults[claim.id] != null && policy.defaults[claim.id] !== ""
                ? policy.defaults[claim.id]
                : claim.fallback;
            return (
              '<article class="check-card">' +
              "<header><div><h3>" +
              esc(claimLabel(claim.id)) +
              "</h3><p>Pass <b class=\"score-ok\">" +
              esc(rules[0].score) +
              "</b> · otherwise <b class=\"score-no\">" +
              esc(fallback) +
              "</b></p></div>" +
              '<div class="bar"><button type="button" class="btn" data-action="edit-check" data-claim="' +
              esc(claim.id) +
              '">Edit</button>' +
              '<button type="button" class="btn danger" data-action="delete-check" data-claim="' +
              esc(claim.id) +
              '">Remove</button></div></header>' +
              '<div class="match-list">' +
              rules
                .map(function (rule, ruleIndex) {
                  const device = deviceById(rule.device);
                  const groups = rule.conditions.length ? rule.conditions : [null];
                  return (
                    (ruleIndex ? '<p class="match-or">OR</p>' : "") +
                    '<section class="match-platform"><h4>' +
                    esc(device ? device.label : rule.device) +
                    "</h4>" +
                    groups
                      .map(function (condition, groupIndex) {
                        const lines = condition
                          ? requirementLines(condition, device)
                          : ["evidence present"];
                        return (
                          (groupIndex ? '<p class="match-or">OR</p>' : "") +
                          '<ul class="match-and">' +
                          lines
                            .map(function (line) {
                              return "<li>" + esc(line) + "</li>";
                            })
                            .join("") +
                          "</ul>"
                        );
                      })
                      .join("") +
                    "</section>"
                  );
                })
                .join("") +
              "</div></article>"
            );
          })
          .join("") +
        "</div>";
    }
    const waiting = !policy.devices.length;
    html +=
      '<div class="add-row' +
      (waiting ? " is-waiting" : "") +
      '"><span>' +
      (waiting ? "Select a platform first" : "Add a check") +
      '</span><div class="chips">' +
      unused
        .map(function (claim) {
          return (
            '<button type="button" class="chip" data-action="edit-check" data-claim="' +
            esc(claim.id) +
            '">' +
            esc(claimLabel(claim.id)) +
            "</button>"
          );
        })
        .join("") +
      "</div></div>";
    return html;
  }

  function paintChrome() {
    const label = document.getElementById("product-label");
    const sub = document.getElementById("product-sub");
    const actions = document.getElementById("header-actions");
    const chrome = {
      "": ["Trustee", "Policy builder", "Trustee policy builder"],
      as: ["AS policy", "Attestation Service", "AS policy · Trustee"],
      kbs: ["KBS policy", "Key Broker Service", "KBS policy · Trustee"],
    };
    const item = chrome[state.kind] || chrome[""];
    if (label) label.textContent = item[0];
    if (sub) sub.textContent = item[1];
    document.title = item[2];
    if (!actions) return;
    actions.innerHTML = state.kind
      ? '<button type="button" class="btn quiet" data-action="choose-kind" data-kind="">All policy types</button>'
      : "";
  }

  function kindCard(kind, className, code, pillClass, pill, name, blurb, go) {
    return (
      '<button type="button" class="kind-card ' +
      className +
      '" data-action="choose-kind" data-kind="' +
      kind +
      '"><span class="kind-top"><span class="kind-code">' +
      esc(code) +
      '</span><span class="pill ' +
      pillClass +
      '">' +
      esc(pill) +
      '</span></span><span class="kind-name">' +
      esc(name) +
      '</span><span class="kind-blurb">' +
      esc(blurb) +
      '</span><span class="kind-go">' +
      esc(go) +
      "</span></button>"
    );
  }

  function gateView() {
    return (
      '<section class="gate"><div class="gate-copy"><h1>Choose a policy type</h1>' +
      '<p class="lead">Trustee scores evidence with an Attestation Service policy, and releases keys with a Key Broker Service policy. AS policies can be drafted here.</p></div>' +
      '<div class="kind-grid">' +
      kindCard(
        "as",
        "kind-as",
        "AS",
        "pill-ok",
        "Available",
        "Attestation Service",
        "Choose which platforms may present evidence, score each trust claim, and download the Rego policy.",
        "Open AS policy",
      ) +
      kindCard(
        "kbs",
        "kind-kbs",
        "KBS",
        "pill-wait",
        "Not supported yet",
        "Key Broker Service",
        "Rules for releasing keys and other resources after attestation. Open this to see the current limit.",
        "Open KBS policy",
      ) +
      "</div></section>"
    );
  }

  function kbsView() {
    return (
      '<section class="unsupported"><p class="pill pill-wait">Not supported yet</p>' +
      "<h1>KBS policies are not supported yet</h1>" +
      '<p class="lead">A Key Broker Service policy decides which keys and resources a workload may receive. This builder does not draft that policy yet. Attestation Service policies are available now.</p>' +
      '<div class="bar"><button type="button" class="btn" data-action="choose-kind" data-kind="">All policy types</button>' +
      '<button type="button" class="btn primary" data-action="choose-kind" data-kind="as">Open AS policy</button></div></section>'
    );
  }

  function view() {
    if (state.kind === "kbs") return kbsView();
    if (state.kind === "as") return asView();
    return gateView();
  }

  function asView() {
    const policy = active();
    const platformCount = policy.devices.length;
    const checkCount = usedClaims(policy).length;
    const tabs =
      state.policies.length < 2
        ? ""
        : '<div class="tabs">' +
          state.policies
            .map(function (item) {
              const on = item.uid === policy.uid ? " is-on" : "";
              return (
                '<button type="button" class="tab' +
                on +
                '" data-action="select-policy" data-policy="' +
                esc(item.uid) +
                '">' +
                esc(item.policyId || "policy") +
                "</button>"
              );
            })
            .join("") +
          "</div>";
    return (
      '<div class="page-head"><h1>Attestation policy</h1>' +
      '<p class="lead">Choose the platforms that may present evidence, then score each trust claim. The Rego file updates as you edit.</p></div>' +
      tabs +
      '<div class="workspace"><section class="panel">' +
      '<section class="block step step-name"><div class="step-head"><h2><span class="num">1</span>Name</h2><div class="bar">' +
      '<button type="button" class="btn" data-action="add-policy">New policy</button>' +
      (state.policies.length > 1
        ? '<button type="button" class="btn danger" data-action="delete-policy">Delete</button>'
        : "") +
      "</div></div><div class=\"pair\">" +
      '<label class="field">Policy id<input data-model="policyId" value="' +
      esc(policy.policyId) +
      '" spellcheck="false" autocomplete="off"><span class="field-hint">Stored with the policy and used as the downloaded file name.</span></label>' +
      '<label class="field">Token entry (submod)<input data-model="submod" value="' +
      esc(policy.submod) +
      '" spellcheck="false" autocomplete="off"><span class="field-hint">Entry name AS reads when it selects this policy.</span></label></div></section>' +
      '<section class="block step step-platforms"><div class="step-head"><h2><span class="num">2</span>Platforms</h2><span class="count' +
      (platformCount ? " is-set" : "") +
      '">' +
      (platformCount ? platformCount + " selected" : "None selected") +
      '</span></div><p class="lead">Which TEEs can use this policy?</p>' +
      teePicker(policy) +
      "</section>" +
      '<section class="block step step-checks"><div class="step-head"><h2><span class="num">3</span>Checks</h2><span class="count' +
      (checkCount ? " is-set" : "") +
      '">' +
      (checkCount ? checkCount + (checkCount === 1 ? " check" : " checks") : "None yet") +
      '</span></div><p class="lead">Each check scores one trust claim. Inside a check, every platform can require different fields.</p>' +
      (state.toast ? '<p class="issues">' + esc(state.toast) + "</p>" : "") +
      checksView(policy) +
      "</section></section>" +
      '<aside class="dock"><div class="dock-top"><div class="dock-title"><h2>Generated Rego</h2><p class="dock-meta"><span id="rego-file"></span><span id="rego-status" class="status"></span></p></div><div class="bar">' +
      '<button type="button" class="btn" id="copy-rego" data-action="copy-rego">Copy</button>' +
      '<button type="button" class="btn primary" id="download-rego" data-action="download-rego">Download</button></div></div>' +
      '<pre id="rego"></pre><p id="issues" class="issues"></p><p id="warnings" class="warnings"></p>' +
      '<div class="bar"><button type="button" class="btn quiet" data-action="download-json">Save project</button>' +
      '<label class="btn quiet file-btn">Open project<input id="load-json" type="file" accept="application/json,.json"></label></div></aside></div>' +
      modalView(policy)
    );
  }

  function refreshOutput() {
    const policy = active();
    const result = rego.generatePolicy(policy);
    const code = document.getElementById("rego");
    const issues = document.getElementById("issues");
    const download = document.getElementById("download-rego");
    if (!code) return;
    code.textContent = result.rego;
    if (issues) issues.textContent = result.errors.join("\n");
    const warnings = document.getElementById("warnings");
    if (warnings) warnings.textContent = result.warnings.join("\n");
    const file = document.getElementById("rego-file");
    if (file) file.textContent = (policy.policyId.trim() || "policy") + ".rego";
    const status = document.getElementById("rego-status");
    if (status) {
      let tone = "ok";
      let label = "Ready";
      if (result.errors.length) {
        tone = "bad";
        label = "Needs attention";
      } else if (!result.ok) {
        tone = "wait";
        label = "Add a check";
      }
      status.className = "status is-" + tone;
      status.textContent = label;
    }
    if (download) {
      download.disabled = !result.ok;
      download.title = result.ok
        ? "Download the Rego file"
        : result.errors[0] || "Add a check before downloading.";
    }
    const tab = document.querySelector('[data-policy="' + policy.uid + '"]');
    if (tab) tab.textContent = policy.policyId || "policy";
  }

  function captureScroll() {
    const modal = document.querySelector(".modal");
    return {
      page: root.pageYOffset || 0,
      modal: modal ? modal.scrollTop : null,
    };
  }

  function restoreScroll(saved, reveal) {
    if (!saved) return;
    function apply() {
      if (typeof root.scrollTo === "function") root.scrollTo(0, saved.page || 0);
      const modal = document.querySelector(".modal");
      if (!modal) return;
      if (saved.modal != null) modal.scrollTop = saved.modal;
      if (!reveal) return;
      const el = modal.querySelector(reveal);
      if (!el) return;
      const modalRect = modal.getBoundingClientRect();
      const elRect = el.getBoundingClientRect();
      if (elRect.bottom > modalRect.bottom - 8) {
        modal.scrollTop += elRect.bottom - modalRect.bottom + 28;
      }
    }
    apply();
    if (root.requestAnimationFrame) root.requestAnimationFrame(apply);
    if (root.setTimeout) {
      root.setTimeout(apply, 0);
      root.setTimeout(apply, 50);
    }
  }

  function renderKept(saved, reveal) {
    paintChrome();
    document.getElementById("app").innerHTML = view();
    refreshOutput();
    restoreScroll(saved, reveal);
  }

  function render() {
    paintChrome();
    document.getElementById("app").innerHTML = view();
    refreshOutput();
  }

  function setChoice(row, value, on) {
    const at = row.choices.indexOf(value);
    if (on && at === -1) row.choices.push(value);
    if (!on && at !== -1) row.choices.splice(at, 1);
  }

  function uncheckOthers(target) {
    const group = target.closest && target.closest(".choices");
    if (!group || !group.querySelectorAll) return;
    const inputs = group.querySelectorAll("input");
    for (let i = 0; i < inputs.length; i++) {
      if (inputs[i] !== target) inputs[i].checked = false;
    }
  }

  function setExclusiveChoice(row, target) {
    if (!row.choices) row.choices = [];
    if (target.dataset.exclusive === "true") {
      if (target.checked) {
        row.choices = [target.dataset.value];
        uncheckOthers(target);
      } else {
        setChoice(row, target.dataset.value, false);
      }
      return;
    }
    setChoice(row, target.dataset.value, target.checked);
  }

  function writeModel(target) {
    const policy = active();
    const model = target.dataset.model;
    const index = target.dataset.index;
    if (model === "policyId") policy.policyId = target.value;
    else if (model === "submod") policy.submod = target.value;
    else if (model === "device") {
      const id = target.dataset.device;
      const has = policy.devices.indexOf(id) !== -1;
      if (target.checked && !has) policy.devices.push(id);
      if (!target.checked && has) {
        policy.devices = policy.devices.filter(function (item) {
          return item !== id;
        });
      }
      state.toast = "";
    } else if (!policy.draft) return;
    else if (model === "draft-score") policy.draft.score = Number(target.value);
    else if (model === "draft-fallback") policy.draft.fallback = Number(target.value);
    else if (model === "branch-device") {
      const branch = branchAt(policy);
      branch.device = target.value;
      branch.rows = [];
    } else if (model === "row-path") {
      const row = clauseAt(policy, target);
      row.custom = target.value === "__custom__";
      if (!row.custom) {
        row.path = target.value;
        row.choices = [];
        row.literal = "";
      }
      syncNests(row, deviceById(branchAt(policy).device));
    } else if (model === "nest-path") {
      const nest = nestAt(policy, target);
      if (nest) {
        const row = clauseAt(policy, target);
        const field = findField(deviceById(branchAt(policy).device), row);
        if (!target.value) {
          nest.custom = false;
          nest.path = "";
          nest.literal = "";
          nest.choices = [];
        } else if (target.value === "__custom__") {
          nest.custom = true;
          nest.path = "";
          nest.literalType = "string";
          nest.literal = "";
          nest.choices = [];
          nest.rhs = "literal";
        } else {
          const spec = nestSpec(field, target.value);
          if (spec) applyNestSpec(nest, spec);
          else nest.path = target.value;
        }
      }
    } else if (model === "nest-pathtext") {
      const nest = nestAt(policy, target);
      if (nest) {
        nest.custom = true;
        nest.path = target.value;
      }
    } else if (model === "nest-type") {
      const nest = nestAt(policy, target);
      if (nest) {
        nest.literalType = target.value;
        if (nest.literalType === "bool" && nest.literal !== "true" && nest.literal !== "false") {
          nest.literal = "true";
        }
      }
    } else if (model === "nest-literal") {
      const nest = nestAt(policy, target);
      if (nest) nest.literal = target.value;
    } else if (model === "nest-ref") {
      const nest = nestAt(policy, target);
      if (nest) nest.refId = target.value.trim();
    } else if (model === "row-pathtext") {
      const row = clauseAt(policy, target);
      if (row) row.path = target.value.trim();
    } else if (model === "row-literal") {
      const row = clauseAt(policy, target);
      if (row) row.literal = target.value;
    } else if (model === "row-ref") {
      const row = clauseAt(policy, target);
      if (row) row.refId = target.value.trim();
    }
  }

  function download(name, text) {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  function copyText(text, button) {
    const previous = button.textContent;
    function done() {
      button.textContent = "Copied";
      root.setTimeout(function () {
        button.textContent = previous;
      }, 1000);
    }
    if (navigator.clipboard && root.isSecureContext) {
      navigator.clipboard.writeText(text).then(done).catch(fallback);
    } else {
      fallback();
    }
    function fallback() {
      const area = document.createElement("textarea");
      area.value = text;
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      area.remove();
      done();
    }
  }

  function projectJson() {
    return JSON.stringify(
      {
        kind: "trustee-as-policy-plan-b",
        version: 1,
        policies: state.policies.map(function (policy) {
          return {
            policyId: policy.policyId,
            submod: policy.submod,
            devices: policy.devices,
            defaults: policy.defaults,
            rules: policy.rules,
          };
        }),
      },
      null,
      2,
    );
  }

  function importProject(data) {
    if (
      !data ||
      data.kind !== "trustee-as-policy-plan-b" ||
      data.version !== 1 ||
      !Array.isArray(data.policies) ||
      !data.policies.length
    ) {
      throw new Error("Unrecognized project file.");
    }
    return data.policies.map(function (raw) {
      const policy = blankPolicy();
      policy.policyId = String(raw.policyId || "");
      policy.submod = String(raw.submod || "");
      policy.devices = Array.isArray(raw.devices)
        ? raw.devices.filter(function (id) {
            return deviceById(id);
          })
        : [];
      policy.defaults = raw.defaults && typeof raw.defaults === "object" ? raw.defaults : {};
      policy.rules = Array.isArray(raw.rules)
        ? raw.rules.map(function (rule) {
            return {
              id: rule.id || uid(),
              claim: rule.claim,
              score: rule.score,
              device: rule.device,
              conditions: Array.isArray(rule.conditions) ? rule.conditions : [],
            };
          })
        : [];
      return policy;
    });
  }

  function onInput(event) {
    const target = event.target;
    if (!target.dataset.model) return;
    writeModel(target);
    refreshOutput();
  }

  function onChange(event) {
    const target = event.target;
    if (target.id === "load-json" && target.files && target.files[0]) {
      const reader = new FileReader();
      reader.onload = function () {
        try {
          state.policies = importProject(JSON.parse(String(reader.result)));
          state.activeId = state.policies[0].uid;
          state.toast = "";
        } catch (error) {
          state.toast = error.message || "Could not open the file.";
        }
        render();
      };
      reader.readAsText(target.files[0]);
      target.value = "";
      return;
    }
    if (target.dataset.action === "toggle-choice") {
      const row = clauseAt(active(), target);
      if (row) setExclusiveChoice(row, target);
      return;
    }
    if (target.dataset.action === "toggle-nest-choice") {
      const nest = nestAt(active(), target);
      if (nest) {
        if (!nest.choices) nest.choices = [];
        setExclusiveChoice(nest, target);
        nest.literalType = "bool";
        nest.rhs = "literal";
        nest.literal = nest.choices[0] || "";
      }
      return;
    }
    if (!target.dataset.model) return;
    writeModel(target);
    if (target.dataset.redraw === "true") render();
    else refreshOutput();
  }

  function onClick(event) {
    const button = event.target.closest("[data-action]");
    if (!button || button.disabled) return;
    const action = button.dataset.action;
    if (action === "choose-kind") {
      state.kind = button.dataset.kind || "";
      state.toast = "";
      render();
      if (typeof root.scrollTo === "function") root.scrollTo(0, 0);
      const heading = document.querySelector("#app h1");
      if (heading && heading.focus) {
        heading.setAttribute("tabindex", "-1");
        heading.focus();
      }
      return;
    }
    const policy = active();
    if (action === "close-modal") {
      if (event.target !== button) return;
      policy.draft = null;
      render();
      return;
    }
    if (action === "add-policy") {
      const created = blankPolicy();
      created.policyId = "policy-" + (state.policies.length + 1);
      state.policies.push(created);
      state.activeId = created.uid;
      render();
    } else if (action === "select-policy") {
      state.activeId = button.dataset.policy;
      state.toast = "";
      render();
    } else if (action === "delete-policy") {
      if (!root.confirm("Delete this policy?")) return;
      state.policies = state.policies.filter(function (item) {
        return item.uid !== policy.uid;
      });
      if (!state.policies.length) state.policies.push(blankPolicy());
      state.activeId = state.policies[0].uid;
      render();
    } else if (action === "edit-check") openCheck(policy, button.dataset.claim);
    else if (action === "delete-check") {
      policy.rules = policy.rules.filter(function (rule) {
        return rule.claim !== button.dataset.claim;
      });
      delete policy.defaults[button.dataset.claim];
      if (policy.draft && policy.draft.claim === button.dataset.claim) policy.draft = null;
      render();
    } else if (action === "focus-branch") {
      policy.draft.focus = button.dataset.id;
      render();
    } else if (action === "add-branch") {
      const used = {};
      policy.draft.branches.forEach(function (branch) {
        used[branch.device] = true;
      });
      const next = selectedDevices(policy).find(function (device) {
        return !used[device.id];
      });
      if (!next) return;
      const branch = newBranch(next.id);
      policy.draft.branches.push(branch);
      policy.draft.focus = branch.id;
      render();
    } else if (action === "delete-branch") {
      if (policy.draft.branches.length < 2) return;
      policy.draft.branches = policy.draft.branches.filter(function (branch) {
        return branch.id !== policy.draft.focus;
      });
      policy.draft.focus = policy.draft.branches[0].id;
      render();
    } else if (action === "add-row") {
      branchAt(policy).rows.push(newRow(branchAt(policy).device));
      render();
    } else if (action === "delete-row") {
      branchAt(policy).rows.splice(Number(button.dataset.index), 1);
      render();
    } else if (action === "row-source") {
      const row = clauseAt(policy, button);
      if (!row) return;
      row.source = button.dataset.value;
      row.custom = false;
      row.choices = [];
      const fields = fieldsFor(deviceById(branchAt(policy).device), row.source);
      row.path = fields[0] ? fields[0].path : "";
      syncNests(row, deviceById(branchAt(policy).device));
      render();
    } else if (action === "row-rhs") {
      const row = clauseAt(policy, button);
      if (row) row.rhs = button.dataset.value;
      renderKept(captureScroll());
    } else if (action === "add-nest") {
      const row = clauseAt(policy, button);
      if (!row) return;
      if (!row.nests) row.nests = [];
      row.nests.push(blankNest());
      const suffix = button.dataset.clause == null || button.dataset.clause === "" ? "m" : button.dataset.clause;
      renderKept(captureScroll(), "#nest-" + button.dataset.index + "-" + suffix + "-" + (row.nests.length - 1));
    } else if (action === "delete-nest") {
      const row = clauseAt(policy, button);
      if (row && row.nests) row.nests.splice(Number(button.dataset.nest), 1);
      renderKept(captureScroll());
    } else if (action === "add-also") {
      const row = branchAt(policy).rows[Number(button.dataset.index)];
      if (!row.also) row.also = [];
      const extra = newRow(branchAt(policy).device);
      extra.also = [];
      row.also.push(extra);
      renderKept(captureScroll(), "#and-" + button.dataset.index + "-" + (row.also.length - 1));
    } else if (action === "delete-also") {
      const row = branchAt(policy).rows[Number(button.dataset.index)];
      if (row && row.also) row.also.splice(Number(button.dataset.clause), 1);
      renderKept(captureScroll());
    } else if (action === "nest-rhs") {
      const nest = nestAt(policy, button);
      if (nest) nest.rhs = button.dataset.value;
      render();
    } else if (action === "save-draft") saveDraft(policy);
    else if (action === "cancel-draft") {
      policy.draft = null;
      render();
    } else if (action === "copy-rego") {
      copyText(document.getElementById("rego").textContent, button);
    } else if (action === "download-rego") {
      const result = rego.generatePolicy(policy);
      if (result.ok) download(policy.policyId.trim() + ".rego", result.rego);
    } else if (action === "download-json") {
      download("as-policy.json", projectJson() + "\n");
    }
  }

  function init() {
    const app = document.getElementById("app");
    if (!app) return;
    const policy = blankPolicy();
    state.policies = [policy];
    state.activeId = policy.uid;
    app.addEventListener("input", onInput);
    app.addEventListener("change", onChange);
    app.addEventListener("click", onClick);
    const header = document.querySelector(".site-header");
    if (header && header.addEventListener) header.addEventListener("click", onClick);
    app.addEventListener("submit", function (event) {
      event.preventDefault();
    });
    if (document.addEventListener) {
      document.addEventListener("keydown", function (event) {
        if (event.key === "Escape" && active().draft) {
          active().draft = null;
          render();
        }
      });
    }
    render();
  }

  if (typeof document !== "undefined") init();
})(typeof globalThis !== "undefined" ? globalThis : this);
