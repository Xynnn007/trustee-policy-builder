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

  const state = { policies: [], activeId: "", toast: "" };

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
    };
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
    return row;
  }

  function conditionFromRow(row, device) {
    const field = findField(device, row);
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
      condition.op = "in";
      condition.literal = closed
        .filter(function (value) {
          return row.choices.indexOf(value) !== -1;
        })
        .join(", ");
      condition.literalType = field.type === "bool" ? "bool" : literalTypeOf(field);
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

  function summarize(condition) {
    if (!condition.path) return "present";
    if (condition.rhs === "reference") return condition.path + " from RVPS";
    if (condition.op === "in") return condition.path + " ∈ {" + condition.literal + "}";
    if (condition.op === "==") return condition.path + " = " + condition.literal;
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
        "</option>";
    });
    if (group !== null) html += "</optgroup>";
    html +=
      '<option value="__custom__"' + (custom ? " selected" : "") + ">Custom path</option>";
    return html;
  }

  function choiceBoxes(row, index, values) {
    return (
      '<div class="choices">' +
      values
        .map(function (value) {
          const on = row.choices.indexOf(value) !== -1;
          return (
            '<label class="choice"><input type="checkbox" data-action="toggle-choice" data-index="' +
            index +
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

  function branchAt(policy) {
    const draft = policy.draft;
    return draft.branches.find(function (branch) {
      return branch.id === draft.focus;
    }) || draft.branches[0];
  }

  function rowView(policy, row, index) {
    const branch = branchAt(policy);
    const device = deviceById(branch.device);
    const fields = fieldsFor(device, row.source);
    const field = findField(device, row);
    const closed = closedSet(field);
    let value = "";
    if (closed) value = choiceBoxes(row, index, closed);
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
    const expect =
      closed
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
      '<article class="row' +
      (row.source === "shared" ? " is-shared" : " is-device") +
      '"><header class="row-top"><span class="row-kicker">Condition ' +
      (index + 1) +
      '</span><div class="seg source">' +
      '<button type="button" class="btn' +
      (row.source !== "shared" ? " primary" : "") +
      '" data-action="row-source" data-index="' +
      index +
      '" data-value="device">This platform</button>' +
      '<button type="button" class="btn' +
      (row.source === "shared" ? " primary" : "") +
      '" data-action="row-source" data-index="' +
      index +
      '" data-value="shared">Shared</button></div>' +
      '<button type="button" class="btn danger" data-action="delete-row" data-index="' +
      index +
      '">Remove</button></header><div class="row-body"><label class="field">Evidence field<select data-model="row-path" data-index="' +
      index +
      '" data-redraw="true">' +
      fieldOptions(fields, row.path, row.custom) +
      "</select>" +
      custom +
      "</label>" +
      expect +
      "</div></article>"
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
      "<h2>When is " +
      esc(claimLabel(draft.claim).toLowerCase()) +
      " trusted?</h2>" +
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
            ? "All of these must match for this platform."
            : "No extra fields. Passing only requires this platform’s evidence.") +
          "</p>" +
          '<div class="rows">' +
          branch.rows
            .map(function (row, index) {
              return rowView(policy, row, index);
            })
            .join("") +
          "</div>" +
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
            '"><h3>' +
            esc(group.name) +
            '</h3><div class="tees">' +
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
              "<ul>" +
              rules
                .map(function (rule) {
                  const device = deviceById(rule.device);
                  const text = rule.conditions.length
                    ? rule.conditions.map(summarize).join(" · ")
                    : "evidence present";
                  return (
                    "<li><strong>" +
                    esc(device ? device.label : rule.device) +
                    "</strong><span>" +
                    esc(text) +
                    "</span></li>"
                  );
                })
                .join("") +
              "</ul></article>"
            );
          })
          .join("") +
        "</div>";
    }
    html +=
      '<div class="add-row"><span>Add a check</span><div class="chips">' +
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

  function view() {
    const policy = active();
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
      tabs +
      '<div class="workspace"><section class="panel">' +
      '<section class="block step step-name"><h2><span class="num">1</span>Name</h2><div class="pair">' +
      '<label class="field">Policy id<input data-model="policyId" value="' +
      esc(policy.policyId) +
      '" spellcheck="false" autocomplete="off"></label>' +
      '<label class="field">Token entry (submod)<input data-model="submod" value="' +
      esc(policy.submod) +
      '" spellcheck="false" autocomplete="off"></label></div>' +
      '<div class="bar"><button type="button" class="btn" data-action="add-policy">New policy</button>' +
      (state.policies.length > 1
        ? '<button type="button" class="btn danger" data-action="delete-policy">Delete</button>'
        : "") +
      "</div></section>" +
      '<section class="block step step-platforms"><h2><span class="num">2</span>Platforms</h2><p class="lead">Which TEEs can use this policy?</p>' +
      teePicker(policy) +
      "</section>" +
      '<section class="block step step-checks"><h2><span class="num">3</span>Checks</h2><p class="lead">Each check scores one trust claim. Inside a check, every platform can require different fields.</p>' +
      (state.toast ? '<p class="issues">' + esc(state.toast) + "</p>" : "") +
      checksView(policy) +
      "</section></section>" +
      '<aside class="dock"><div class="dock-top"><h2>Generated Rego</h2><div class="bar">' +
      '<button type="button" class="btn" id="copy-rego" data-action="copy-rego">Copy</button>' +
      '<button type="button" class="btn primary" id="download-rego" data-action="download-rego">Download</button></div></div>' +
      '<pre id="rego"></pre><p id="issues" class="issues"></p>' +
      '<div class="bar"><button type="button" class="btn quiet" data-action="download-json">Save project</button>' +
      '<label class="btn quiet file-btn">Open<input id="load-json" type="file" accept="application/json,.json"></label></div></aside></div>' +
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
    if (download) download.disabled = !result.ok;
    const tab = document.querySelector('[data-policy="' + policy.uid + '"]');
    if (tab) tab.textContent = policy.policyId || "policy";
  }

  function render() {
    document.getElementById("app").innerHTML = view();
    refreshOutput();
  }

  function setChoice(row, value, on) {
    const at = row.choices.indexOf(value);
    if (on && at === -1) row.choices.push(value);
    if (!on && at !== -1) row.choices.splice(at, 1);
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
      const row = branchAt(policy).rows[Number(index)];
      row.custom = target.value === "__custom__";
      if (!row.custom) {
        row.path = target.value;
        row.choices = [];
        row.literal = "";
      }
    } else if (model === "row-pathtext") {
      branchAt(policy).rows[Number(index)].path = target.value.trim();
    } else if (model === "row-literal") {
      branchAt(policy).rows[Number(index)].literal = target.value;
    } else if (model === "row-ref") {
      branchAt(policy).rows[Number(index)].refId = target.value.trim();
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
      const row = branchAt(active()).rows[Number(target.dataset.index)];
      if (row) setChoice(row, target.dataset.value, target.checked);
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
    const policy = active();
    const action = button.dataset.action;
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
      const row = branchAt(policy).rows[Number(button.dataset.index)];
      row.source = button.dataset.value;
      row.custom = false;
      row.choices = [];
      const fields = fieldsFor(deviceById(branchAt(policy).device), row.source);
      row.path = fields[0] ? fields[0].path : "";
      render();
    } else if (action === "row-rhs") {
      branchAt(policy).rows[Number(button.dataset.index)].rhs = button.dataset.value;
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
