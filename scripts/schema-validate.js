const fs = require('node:fs');
const path = require('node:path');
const Ajv = require('ajv');
const addFormats = require('ajv-formats');

const schema = JSON.parse(fs.readFileSync('schema/state.schema.json', 'utf8'));
const draft = schema.$schema;
const AjvClass = draft?.includes('2020-12') ? require('ajv/dist/2020').default
  : draft?.includes('2019-09') ? require('ajv/dist/2019').default : Ajv;
const ajv = new AjvClass({ allErrors: true, strict: false });
if (JSON.stringify(schema).includes('"format"')) addFormats(ajv);
const validate = ajv.compile(schema);
let failed = false;

function check(name, data, expected) {
  const actual = validate(data);
  const pass = actual === expected;
  console.log(`${pass ? 'PASS' : 'FAIL'} ${name}`);
  if (!pass) {
    failed = true;
    console.error(validate.errors || 'unexpected validation result');
  }
}

for (const file of fs.readdirSync('schema/examples').filter((name) => name.endsWith('.json')).sort()) {
  check(`example ${file}`, JSON.parse(fs.readFileSync(path.join('schema/examples', file), 'utf8')), true);
}
const example = JSON.parse(fs.readFileSync('schema/examples/state.hop.example.json', 'utf8'));
const interfaceExample = JSON.parse(fs.readFileSync('schema/examples/state.example.json', 'utf8'));
const probeExample = JSON.parse(fs.readFileSync('schema/examples/state.probe.example.json', 'utf8'));
const negative = [
  ['bad private key pattern', interfaceExample, (data) => { data.interfaces[0].private_key = 'invalid'; }],
  ['listen_port 70000', interfaceExample, (data) => { data.interfaces[0].listen_port = 70000; }],
  ['mode bogus', interfaceExample, (data) => { data.interfaces[0].mode = 'bogus'; }],
  ['persistent_keepalive 70000', probeExample, (data) => { data.interfaces[0].peers[0].persistent_keepalive = 70000; }],
  ['server listen_port 0', interfaceExample, (data) => { data.interfaces[0].listen_port = 0; }],
  ['hop bad backend_ip', example, (data) => { data.hop.routes[0].backend_ip = 'not-an-ip'; }],
  ['hop route port 0', example, (data) => { data.hop.routes[0].listen_port = 0; }],
  ['hop missing wan_interface', example, (data) => { delete data.hop.wan_interface; }],
  ['unknown extra hop property', example, (data) => { data.hop.extra = true; }],
];
for (const [name, fixture, mutate] of negative) {
  const data = structuredClone(fixture);
  mutate(data);
  check(name, data, false);
}
process.exitCode = failed ? 1 : 0;
