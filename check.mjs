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
assert(rfc.rego.includes("} else := 2 if {"), "else chain\n" + rfc.rego);
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
fire("change", { dataset: { action: "toggle-choice", index: "0", value: "false" }, checked: true });
fire("click", button("add-branch"));
assert(app.innerHTML.includes("AMD SEV-SNP") || app.innerHTML.includes("data-action=\"focus-branch\""), "second platform missing");
fire("click", button("save-draft"));
assert(elements.get("rego").textContent.includes("input.tdx.td_attributes.debug in {false}"), "checkbox did not become in\n" + elements.get("rego").textContent);
assert(elements.get("rego").textContent.includes("} else := 2 if {"), "multi-tee else chain missing\n" + elements.get("rego").textContent);
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

if (failures.length) {
  console.error(failures.join("\n\n"));
  process.exit(1);
}
console.log("ok", AS_CATALOG.devices.length, "devices");
