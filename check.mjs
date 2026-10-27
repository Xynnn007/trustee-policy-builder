import fs from "fs";
import path from "path";
import vm from "vm";
import { fileURLToPath } from "url";

const dir = path.dirname(fileURLToPath(import.meta.url));
const context = { console };
context.globalThis = context;
vm.createContext(context);
for (const file of ["catalog.js", "rego.js", "presets.js"]) {
  vm.runInContext(fs.readFileSync(path.join(dir, file), "utf8"), context, { filename: file });
}

const { AS_CATALOG, AS_REGO, AS_PRESETS } = context;
const failures = [];

function assert(cond, message) {
  if (!cond) failures.push(message);
}

function policyFromPreset(preset) {
  return {
    policyId: preset.policyId,
    submod: preset.submod,
    devices: preset.devices.slice(),
    defaults: Object.assign({}, preset.defaults),
    rules: preset.rules.map(function (rule) {
      return Object.assign({}, rule);
    }),
  };
}

const uefi = AS_CATALOG.devices.find(function (device) { return device.id === "tdx"; }).fields.find(function (field) {
  return field.path === "uefi_event_logs";
});
assert(uefi.nestFields.some(function (field) {
  return field.path === "event_type" && field.suggestions.indexOf("EV_SEPARATOR") !== -1 && field.suggestions.indexOf("EV_EFI_ACTION") !== -1;
}), "event_type should be an enum");
assert(uefi.nestFields.some(function (field) {
  return field.path === "digest_matches_event" && field.type === "bool";
}), "digest_matches_event should be bool");
assert(uefi.nestFields.some(function (field) {
  return field.path === "digests[_].alg" && field.suggestions.indexOf("SHA-256") !== -1;
}), "digest alg should be an enum");

AS_CATALOG.devices.forEach(function (device) {
  const seen = new Set();
  device.fields.forEach(function (field) {
    const parsed = AS_REGO.parsePath(field.path);
    assert(parsed, device.id + " path does not parse: " + field.path);
    assert(!seen.has(field.path), device.id + " duplicate path " + field.path);
    seen.add(field.path);
  });
  assert(device.fields.length > 0, device.id + " has no fields");
});

const az = AS_CATALOG.devices.find(function (device) { return device.id === "az-tdx-vtpm"; });
const tdx = AS_CATALOG.devices.find(function (device) { return device.id === "tdx"; });
assert(az.fields.length > tdx.fields.length, "azure tdx should inherit tdx fields and add PCRs");
assert(az.fields.some(function (field) { return field.path === "tpm.pcr11"; }), "missing pcr11");
assert(az.fields.some(function (field) { return field.path === "td_attributes.debug"; }), "azure lost tdx debug");

const rfc = AS_REGO.generatePolicy(policyFromPreset(AS_PRESETS.find(function (preset) { return preset.id === "rfc-cpu"; })));
assert(rfc.ok, "rfc preset not ok: " + rfc.errors.join("; "));
assert(rfc.rego.includes('devices := ["tdx", "snp"]'), "device order\n" + rfc.rego);
assert(rfc.rego.includes('submod := "cpu"'), "submod");
assert(rfc.rego.includes("input.tdx.td_attributes.debug == false"), "debug compare\n" + rfc.rego);
assert((rfc.rego.match(/hardware := 2 if \{/g) || []).length === 2, "one if per alternative\n" + rfc.rego);
assert(!rfc.rego.includes("} else := 2 if {"), "same score should be separate if blocks\n" + rfc.rego);
assert(rfc.rego.includes("\tinput.snp"), "snp presence");
assert(rfc.rego.includes("default hardware := 97"), "default");
assert(rfc.rego.includes('"hardware": hardware'), "trust claim");
assert(!rfc.rego.includes('"executables"'), "unused claim leaked");

const measure = AS_REGO.generatePolicy(policyFromPreset(AS_PRESETS.find(function (preset) { return preset.id === "tdx-measure"; })));
assert(measure.ok, measure.errors.join("; "));
assert(measure.rego.includes('input.tdx.quote.body.mr_td in query_reference_value("mr_td")'), "rvps in\n" + measure.rego);
assert(measure.rego.includes('input.tdx.tcb_status == "UpToDate"'), "tcb");

const gpu = AS_REGO.generatePolicy(policyFromPreset(AS_PRESETS.find(function (preset) { return preset.id === "nvidia-gpu"; })));
assert(gpu.ok, gpu.errors.join("; "));
assert(gpu.rego.includes('devices := ["nvidia-gpu"]'), gpu.rego);
assert(gpu.rego.includes('input.nvidia["x-nvidia-gpu-attestation-report-parsed"]'), "nras flag\n" + gpu.rego);
assert(gpu.rego.includes('input.nvidia["x-nvidia-gpu-attestation-report-cert-chain"]["x-nvidia-cert-ocsp-status"] == "good"'), "nested nras\n" + gpu.rego);
assert(gpu.rego.includes('input.nvidia["x-nvidia-gpu-vbios-version"] in query_reference_value("allowed_vbios_versions")'), "vbios");
assert(gpu.rego.includes("} else := 3 if {"), "config else");

const runtime = AS_REGO.generatePolicy(policyFromPreset(AS_PRESETS.find(function (preset) { return preset.id === "runtime"; })));
assert(runtime.ok, runtime.errors.join("; "));
assert(runtime.rego.includes('input.init_data_claims.runtime == "runtime1"'), "shared path\n" + runtime.rego);
assert(runtime.rego.includes("\tinput.tdx"), "tdx gate");
assert(!runtime.rego.includes("input.tdx.init_data_claims"), "shared path was prefixed");

const azure = AS_REGO.generatePolicy({
  policyId: "az",
  submod: "firmware",
  devices: ["az-tdx-vtpm"],
  defaults: { hardware: 97 },
  rules: [{
    claim: "hardware",
    score: 2,
    device: "az-tdx-vtpm",
    conditions: [{
      kind: "compare",
      source: "device",
      pathMode: "catalog",
      path: "tpm.pcr11",
      op: "in",
      rhs: "reference",
      refId: "tdx_pcr11",
      literalType: "string",
      literal: "",
    }],
  }],
});
assert(azure.ok, azure.errors.join("; "));
assert(azure.rego.includes('input["az-tdx-vtpm"].tpm.pcr11 in query_reference_value("tdx_pcr11")'), azure.rego);

const sgx = AS_REGO.generatePolicy({
  policyId: "sgx",
  submod: "enclave",
  devices: ["sgx"],
  defaults: { executables: 33 },
  rules: [{
    claim: "executables",
    score: 3,
    device: "sgx",
    conditions: [{
      kind: "compare",
      source: "device",
      pathMode: "catalog",
      path: 'body["attributes.flags"]',
      op: "==",
      rhs: "literal",
      literalType: "string",
      literal: 'a"b',
      refId: "",
    }],
  }],
});
assert(sgx.ok, sgx.errors.join("; "));
assert(sgx.rego.includes('input.sgx.body["attributes.flags"] == "a\\"b"'), sgx.rego);

const custom = AS_REGO.generatePolicy({
  policyId: "events",
  submod: "boot",
  devices: ["tdx"],
  defaults: { executables: 33 },
  rules: [{
    claim: "executables",
    score: 3,
    device: "tdx",
    conditions: [{ kind: "custom", text: "event := input.tdx.uefi_event_logs[_]\nevent.type_name == \"EV_SEPARATOR\"" }],
  }],
});
assert(custom.ok, custom.errors.join("; "));
assert(custom.rego.includes("event.type_name == \"EV_SEPARATOR\""), custom.rego);

const wild = AS_REGO.parsePath("containers[_].name");
assert(wild && wild.length === 3 && wild[1].wild === true, "wildcard segment");
const indexed = AS_REGO.parsePath("items[0].name");
assert(indexed && indexed[1].index === 0, "index segment");
assert(AS_REGO.parsePath('body["attributes.flags"]'), "quoted path still parses");
assert(!AS_REGO.parsePath("[_].name"), "wildcard cannot start a path");

const claims = AS_REGO.generatePolicy({
  policyId: "claims",
  submod: "runtime",
  devices: ["tdx"],
  defaults: { executables: 33 },
  rules: [{
    claim: "executables",
    score: 3,
    device: "tdx",
    conditions: [{
      kind: "compare",
      source: "shared",
      pathMode: "nested",
      path: "init_data_claims",
      nests: [
        { path: "runtime", rhs: "literal", literalType: "string", literal: "runtime1", refId: "" },
        { path: "agent_policy_claims.version", rhs: "literal", literalType: "number", literal: "2", refId: "" },
        { path: "containers[_].name", rhs: "literal", literalType: "string", literal: "pause", refId: "" },
      ],
    }, {
      kind: "compare",
      source: "shared",
      pathMode: "nested",
      path: "runtime_data_claims",
      nests: [
        { path: "key", rhs: "reference", literalType: "string", literal: "", refId: "rt" },
      ],
    }],
  }],
});
assert(claims.ok, claims.errors.join("; "));
assert(claims.rego.includes('input.init_data_claims.runtime == "runtime1"'), claims.rego);
assert(claims.rego.includes("input.init_data_claims.agent_policy_claims.version == 2"), claims.rego);
assert(claims.rego.includes('input.init_data_claims.containers[_].name == "pause"'), claims.rego);
assert(claims.rego.includes('input.runtime_data_claims.key in query_reference_value("rt")'), claims.rego);
assert(!claims.rego.includes("input.tdx.init_data_claims"), claims.rego);

const events = AS_REGO.generatePolicy({
  policyId: "events2",
  submod: "boot",
  devices: ["tdx", "az-tdx-vtpm"],
  defaults: { executables: 33 },
  rules: [{
    claim: "executables",
    score: 3,
    device: "tdx",
    conditions: [{
      kind: "compare",
      source: "device",
      pathMode: "nested",
      path: "uefi_event_logs",
      nests: [
        { path: "event_type", rhs: "literal", literalType: "string", literal: "EV_SEPARATOR", refId: "" },
        { path: "digest_matches_event", rhs: "literal", literalType: "bool", literal: "true", refId: "" },
        { path: "details.data.domain", rhs: "literal", literalType: "string", literal: "kbc", refId: "" },
      ],
    }, {
      kind: "compare",
      source: "device",
      pathMode: "nested",
      path: "uefi_event_logs",
      nests: [
        { path: "event_type", rhs: "literal", literalType: "string", literal: "EV_ACTION", refId: "" },
      ],
    }],
  }, {
    claim: "executables",
    score: 3,
    device: "az-tdx-vtpm",
    conditions: [{
      kind: "compare",
      source: "device",
      pathMode: "nested",
      path: "uefi_event_logs",
      nests: [
        { path: "details.string", rhs: "literal", literalType: "string", literal: "boot", refId: "" },
      ],
    }],
  }],
});
assert(events.ok, events.errors.join("; "));
assert(events.rego.includes("ev0 := input.tdx.uefi_event_logs[_]"), events.rego);
assert(events.rego.includes('ev0.event_type == "EV_SEPARATOR"'), events.rego);
assert(events.rego.includes("ev0.digest_matches_event == true"), events.rego);
assert(events.rego.includes('ev0.details.data.domain == "kbc"'), events.rego);
const eventBlocks = events.rego.split("executables := 3 if {").slice(1);
assert(eventBlocks.length >= 2, "event conditions should be separate if blocks\n" + events.rego);
assert(eventBlocks[0].includes('ev0.event_type == "EV_SEPARATOR"'), events.rego);
assert(eventBlocks[1].includes("ev0 := input.tdx.uefi_event_logs[_]"), events.rego);
assert(eventBlocks[1].includes('ev0.event_type == "EV_ACTION"'), events.rego);
assert(events.rego.includes('ev0 := input["az-tdx-vtpm"].uefi_event_logs[_]'), events.rego);
assert(events.rego.includes('ev0.details.string == "boot"'), events.rego);

const mixed = AS_REGO.generatePolicy({
  policyId: "mix",
  submod: "cpu",
  devices: ["tdx"],
  defaults: { hardware: 97 },
  rules: [{
    claim: "hardware",
    score: 2,
    device: "tdx",
    conditions: [{
      kind: "compare",
      source: "device",
      pathMode: "nested",
      path: "uefi_event_logs",
      nests: [{ path: "event_type", rhs: "literal", literalType: "string", literal: "EV_SEPARATOR", refId: "", choices: [] }],
      also: [{
        kind: "compare",
        source: "device",
        pathMode: "catalog",
        path: "tcb_status",
        op: "==",
        rhs: "literal",
        literalType: "string",
        literal: "UpToDate",
        refId: "",
      }],
    }],
  }],
});
assert(mixed.ok, mixed.errors.join("; "));
const mixedBody = mixed.rego.split("hardware := 2 if {")[1].split("}")[0];
assert(mixedBody.includes('ev0.event_type == "EV_SEPARATOR"'), mixed.rego);
assert(mixedBody.includes('input.tdx.tcb_status == "UpToDate"'), mixed.rego);
assert(mixedBody.indexOf("else") === -1, mixed.rego);

const quote = AS_REGO.generatePolicy({
  policyId: "quote",
  submod: "cpu",
  devices: ["tdx"],
  defaults: { hardware: 97 },
  rules: [{
    claim: "hardware",
    score: 2,
    device: "tdx",
    conditions: [{
      kind: "compare",
      source: "device",
      pathMode: "catalog",
      path: "quote.type",
      op: "==",
      rhs: "literal",
      literalType: "string",
      literal: "0300",
      refId: "",
    }, {
      kind: "compare",
      source: "device",
      pathMode: "catalog",
      path: "tcb_status",
      op: "in",
      rhs: "literal",
      literalType: "string",
      literal: "UpToDate, ConfigurationNeeded",
      refId: "",
    }],
  }],
});
assert(quote.ok, quote.errors.join("; "));
assert(quote.rego.includes("# TDX 1.5"), quote.rego);
assert(quote.rego.includes('input.tdx.quote.type == "0300"'), quote.rego);
assert(quote.rego.includes('input.tdx.tcb_status in {"UpToDate", "ConfigurationNeeded"}'), quote.rego);

const badNest = AS_REGO.generatePolicy({
  policyId: "badnest",
  submod: "runtime",
  devices: ["tdx"],
  defaults: {},
  rules: [{
    claim: "executables",
    score: 3,
    device: "tdx",
    conditions: [{
      kind: "compare",
      source: "shared",
      pathMode: "nested",
      path: "init_data_claims",
      nests: [{ path: "a b", rhs: "literal", literalType: "string", literal: "x", refId: "" }],
    }],
  }],
});
assert(!badNest.ok, "invalid nested path should fail");
assert(!badNest.rego.includes("trust_claims :="), badNest.rego);

const broken = AS_REGO.generatePolicy({
  policyId: "broken",
  submod: "boot",
  devices: ["tdx"],
  defaults: {},
  rules: [{
    claim: "hardware",
    score: 2,
    device: "tdx",
    conditions: [{ kind: "custom", text: "input.tdx.quote { true }" }],
  }],
});
assert(!broken.ok, "brace injection should fail");
assert(!broken.rego.includes("trust_claims :="), "invalid rule must not be emitted\n" + broken.rego);

const sample = AS_REGO.generatePolicy({
  policyId: "sample",
  submod: "sample",
  devices: ["sample"],
  defaults: { hardware: 97 },
  rules: [{
    claim: "hardware",
    score: 2,
    device: "sample",
    conditions: [],
  }],
});
assert(sample.ok, sample.errors.join("; "));
assert(sample.warnings.some(function (warning) { return warning.includes("sample"); }), sample.warnings.join("\n"));

const both = AS_REGO.generatePolicy({
  policyId: "nv",
  submod: "nv",
  devices: ["nvidia-gpu", "nvidia-switch"],
  defaults: {},
  rules: [],
});
assert(both.warnings.some(function (warning) { return warning.includes("nvidia-gpu"); }), both.warnings.join("\n"));

const ui = { console, confirm: function () { return true; } };
ui.globalThis = ui;
const elements = new Map();
function makeEl(id) {
  const el = { id: id, textContent: "", disabled: false, value: "", dataset: {} };
  let html = "";
  Object.defineProperty(el, "innerHTML", {
    get: function () { return html; },
    set: function (value) {
      html = String(value);
      const ids = html.matchAll(/\sid="([^"]+)"/g);
      for (const match of ids) {
        if (!elements.has(match[1])) elements.set(match[1], makeEl(match[1]));
      }
    },
  });
  el.addEventListener = function (type, fn) {
    el.listeners = el.listeners || {};
    (el.listeners[type] = el.listeners[type] || []).push(fn);
  };
  return el;
}
const app = makeEl("app");
elements.set("app", app);
ui.document = {
  getElementById: function (id) { return elements.get(id) || null; },
  querySelector: function (sel) {
    const match = /data-policy="([^"]+)"/.exec(sel);
    if (!match || !app.innerHTML.includes('data-policy="' + match[1] + '"')) return null;
    return { textContent: "" };
  },
  createElement: function () { return makeEl("tmp"); },
  execCommand: function () { return true; },
  body: { appendChild: function () {}, removeChild: function () {} },
};
vm.createContext(ui);
for (const file of ["catalog.js", "rego.js", "presets.js", "app.js"]) {
  vm.runInContext(fs.readFileSync(path.join(dir, file), "utf8"), ui, { filename: file });
}
assert(app.innerHTML.includes("Choose a policy type"), "missing policy type choice");
assert(app.innerHTML.includes("Key Broker Service"), "missing KBS choice");
assert(!app.innerHTML.includes("step-name"), "builder should wait for a policy type");
fire("click", button("choose-kind", { kind: "kbs" }));
assert(app.innerHTML.includes("not supported yet"), "KBS should say it is not supported");
assert(!app.innerHTML.includes("step-platforms"), "KBS should not open the AS builder");
fire("click", button("choose-kind", { kind: "as" }));
assert(app.innerHTML.includes("step-name") && app.innerHTML.includes(">Name</h2>"), "missing name step");
assert(app.innerHTML.includes("step-platforms") && app.innerHTML.includes(">Platforms</h2>"), "missing platforms step");
assert(app.innerHTML.includes("step-checks") && app.innerHTML.includes(">Checks</h2>"), "missing checks step");
assert(app.innerHTML.includes("Hardware"), "missing hardware chip");
assert(!app.innerHTML.includes("GitHub Pages"), "publish section still on the page");
assert(elements.get("download-rego").disabled === true, "download should wait for a claim");

function fire(type, target) {
  (app.listeners[type] || []).forEach(function (fn) { fn({ target: target }); });
}
function button(action, extra) {
  const node = { disabled: false, dataset: Object.assign({ action: action }, extra || {}), textContent: action };
  node.closest = function () { return node; };
  return node;
}
fire("change", { dataset: { model: "device", device: "tdx", redraw: "true" }, checked: true });
fire("change", { dataset: { model: "device", device: "snp", redraw: "true" }, checked: true });
fire("click", button("edit-check", { claim: "hardware" }));
assert(app.innerHTML.includes("When is hardware trusted?"), "check dialog did not open");
fire("click", button("add-row"));
assert(app.innerHTML.includes("false"), "bool field should be checkboxes");
assert(app.innerHTML.includes("AND another field"), "condition should offer an AND field");
fire("change", { dataset: { action: "toggle-choice", index: "0", value: "false" }, checked: true });
fire("click", button("add-branch"));
assert(app.innerHTML.includes("AMD SEV-SNP") || app.innerHTML.includes("data-action=\"focus-branch\""), "second platform missing");
fire("click", button("save-draft"));
assert(elements.get("rego").textContent.includes("input.tdx.td_attributes.debug == false"), "bool should be equals\n" + elements.get("rego").textContent);
assert(!elements.get("rego").textContent.includes("debug in {"), "bool should not use in\n" + elements.get("rego").textContent);
assert((elements.get("rego").textContent.match(/hardware := 2 if \{/g) || []).length === 2, "each platform is its own if\n" + elements.get("rego").textContent);
assert(elements.get("rego").textContent.includes("\tinput.snp"), "snp branch missing\n" + elements.get("rego").textContent);
assert(elements.get("download-rego").disabled === false, "download stayed disabled");
assert(app.innerHTML.includes("Intel TDX") && app.innerHTML.includes("AMD SEV-SNP"), "check card should list both platforms");
fire("click", button("edit-check", { claim: "hardware" }));
assert(app.innerHTML.includes('data-value="false" checked'), "edit did not restore the checkbox");
fire("click", button("cancel-draft"));
fire("click", button("edit-check", { claim: "executables" }));
fire("click", button("add-row"));
fire("change", { dataset: { model: "row-path", index: "0", redraw: "true" }, value: "quote.body.mr_td" });
fire("click", button("row-rhs", { index: "0", value: "reference" }));
fire("input", { dataset: { model: "row-ref", index: "0" }, value: "mr_td" });
fire("click", button("save-draft"));
assert(elements.get("rego").textContent.includes('query_reference_value("mr_td")'), "RVPS key missing\n" + elements.get("rego").textContent);
fire("click", button("delete-check", { claim: "hardware" }));
assert(!elements.get("rego").textContent.includes("in {false}"), "hardware check not deleted");
assert(elements.get("rego").textContent.includes('query_reference_value("mr_td")'), "deleted the wrong check");
fire("click", button("edit-check", { claim: "configuration" }));
fire("click", button("add-row"));
fire("click", button("row-source", { index: "0", value: "shared" }));
fire("change", { dataset: { model: "row-path", index: "0", redraw: "true" }, value: "init_data_claims" });
assert(app.innerHTML.includes("JSON fields"), "nested JSON editor missing");
assert(app.innerHTML.includes("Add JSON field"), "missing add JSON field");
fire("input", { dataset: { model: "nest-path", index: "0", nest: "0" }, value: "runtime" });
fire("input", { dataset: { model: "nest-literal", index: "0", nest: "0" }, value: "runtime1" });
fire("click", button("add-nest", { index: "0" }));
fire("input", { dataset: { model: "nest-path", index: "0", nest: "1" }, value: "containers[_].name" });
fire("input", { dataset: { model: "nest-literal", index: "0", nest: "1" }, value: "pause" });
fire("click", button("save-draft"));
assert(elements.get("rego").textContent.includes('input.init_data_claims.runtime == "runtime1"'), "nested claim missing\n" + elements.get("rego").textContent);
assert(elements.get("rego").textContent.includes('input.init_data_claims.containers[_].name == "pause"'), "nested list field missing\n" + elements.get("rego").textContent);
fire("click", button("edit-check", { claim: "configuration" }));
assert(app.innerHTML.includes('value="runtime"'), "edit did not restore the JSON field");
fire("click", button("cancel-draft"));
fire("click", button("edit-check", { claim: "file-system" }));
fire("click", button("add-row"));
fire("change", { dataset: { model: "row-path", index: "0", redraw: "true" }, value: "uefi_event_logs" });
assert(app.innerHTML.includes("EV_SEPARATOR"), "event type menu missing");
assert(app.innerHTML.includes("digest_matches_event"), "known event fields missing");
fire("change", { dataset: { model: "nest-path", index: "0", nest: "0", redraw: "true" }, value: "digest_matches_event" });
assert(app.innerHTML.includes('data-action="toggle-nest-choice"'), "bool JSON field should be checkboxes");
fire("change", { dataset: { model: "nest-path", index: "0", nest: "0", redraw: "true" }, value: "event_type" });
fire("change", { dataset: { model: "nest-literal", index: "0", nest: "0" }, value: "EV_SEPARATOR" });
fire("click", button("save-draft"));
assert(elements.get("rego").textContent.includes('ev0.event_type == "EV_SEPARATOR"'), "event type menu did not save\n" + elements.get("rego").textContent);
fire("click", button("choose-kind", { kind: "kbs" }));
fire("click", button("choose-kind", { kind: "as" }));
assert(elements.get("rego").textContent.includes('query_reference_value("mr_td")'), "leaving KBS dropped the AS policy");

if (failures.length) {
  console.error(failures.join("\n\n"));
  process.exit(1);
}
console.log("ok", AS_CATALOG.devices.length, "devices");
