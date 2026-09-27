const target = process.env.NOCKLOCK_PROBE_TARGET || "https://api.anthropic.com/";

console.log(`node_version=${process.version}`);
console.log(`target=${target}`);
console.log(`HTTPS_PROXY=${process.env.HTTPS_PROXY || ""}`);
console.log(`NODE_USE_ENV_PROXY=${process.env.NODE_USE_ENV_PROXY || ""}`);

try {
  const res = await fetch(target, {
    method: "GET",
    headers: {
      "user-agent": "nocklock-n10753-probe",
    },
  });
  const body = await res.text();
  console.log(`fetch_status=${res.status}`);
  console.log(`fetch_body_prefix=${JSON.stringify(body.slice(0, 120))}`);
} catch (err) {
  console.log(`fetch_error_name=${err?.name || ""}`);
  console.log(`fetch_error_message=${err?.message || String(err)}`);
  if (err?.cause) {
    console.log(`fetch_error_cause=${err.cause?.code || err.cause?.message || String(err.cause)}`);
  }
  process.exitCode = 1;
}
