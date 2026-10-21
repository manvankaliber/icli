struct Params {
  time: f32,
  activity: f32,
  resolution: vec2f,
  mouse: vec2f,
  momentum: vec2f,
}

@group(0) @binding(0) var<uniform> params: Params;

fn hash(p: vec2f) -> f32 {
  return fract(sin(dot(p, vec2f(127.1, 311.7))) * 43758.5453);
}

fn noise(p: vec2f) -> f32 {
  let i = floor(p);
  let f = fract(p);
  let u = f * f * (3.0 - 2.0 * f);
  return mix(mix(hash(i), hash(i + vec2f(1.0, 0.0)), u.x),
    mix(hash(i + vec2f(0.0, 1.0)), hash(i + vec2f(1.0)), u.x), u.y);
}

fn gaussian(x: f32, width: f32) -> f32 {
  let q = x / width;
  return exp(-q * q);
}

// Wavelengths follow slightly different paths through the imperfect glass.
fn dispersion(d: f32, center: f32, spread: f32, blur: f32) -> vec3f {
  let red = gaussian(d - center - spread * 1.05, blur);
  let amber = gaussian(d - center - spread * 0.45, blur * 0.91);
  let gold = gaussian(d - center, blur * 0.82);
  let blue = gaussian(d - center + spread * 0.88, blur * 0.92);
  let violet = gaussian(d - center + spread * 1.18, blur);
  return red * vec3f(1.0, 0.075, 0.018)
    + amber * vec3f(1.0, 0.40, 0.035) * 0.65
    + gold * vec3f(1.0, 0.83, 0.19) * 0.72
    + blue * vec3f(0.035, 0.19, 1.0) * 0.95
    + violet * vec3f(0.25, 0.12, 0.74) * 0.20;
}

fn windowLight(d: f32, s: f32, pointerD: f32, pointerS: f32, seed: f32) -> vec3f {
  if (d > 0.42) { return vec3f(0.0); }
  let t = params.time * 0.045;
  let glass = noise(vec2f(s * 5.2 + seed, t + seed)) - 0.5;
  let detail = noise(vec2f(s * 15.0 - t, seed + t * 0.3)) - 0.5;
  let wave = sin(s * 9.0 + seed + t) * 0.019 + glass * 0.037 + detail * 0.007;
  let approach = exp(-pointerD * 9.0) * params.activity;
  let nearby = gaussian(s - pointerS, 0.24);
  let energy = 0.32 + approach * (0.45 + nearby * 1.55);
  let flow = dot(params.momentum, vec2f(0.6, 0.4));
  let bend = nearby * approach * sin(s * 15.0 + t * 2.0) * (0.004 + abs(flow) * 0.05);
  let center = 0.045 + wave + bend + sin(s * 5.0 + seed) * 0.023;
  let spread = 0.034 + glass * 0.012;
  let aperture = 0.025
    + gaussian(s - (0.25 + sin(seed) * 0.16), 0.14) * 1.15
    + gaussian(s - (0.78 + cos(seed) * 0.10), 0.12) * 0.75
    + nearby * approach * 0.35;

  var light = dispersion(d, center, spread, 0.019) * 0.75;
  light += dispersion(d, center + 0.017, spread * 1.8, 0.073) * 0.20;
  // Fine, imperfect filaments mark the focal edges of the refracted light.
  light += dispersion(d, center + 0.021 + detail * 0.018, spread, 0.007) * 0.13;
  light += dispersion(d, center + 0.061 + glass * 0.025, spread * 1.15, 0.011) * 0.10;
  // Faint shafts reach inward and dissolve before reaching the text.
  let shaft = pow(0.5 + 0.5 * sin(s * 48.0 + glass * 10.0 + seed), 8.0);
  light += dispersion(d, 0.10 + wave, spread * 2.0, 0.16) * shaft * 0.065;
  let edgeBloom = exp(-d * 22.0) * (0.045 + approach * nearby * 0.09);
  light += vec3f(0.70, 0.76, 1.0) * edgeBloom;
  return light * energy * aperture * (1.0 - smoothstep(0.12, 0.42, d));
}

@fragment
fn fs_main(@builtin(position) position: vec4f) -> @location(0) vec4f {
  let resolution = max(params.resolution, vec2f(1.0));
  let uv = position.xy / resolution;
  let aspect = resolution.x / resolution.y;
  // Pointer and fragment coordinates both use a top-left origin.
  var light = windowLight(uv.x * aspect, uv.y, params.mouse.x * aspect, params.mouse.y, 1.4);
  light += windowLight((1.0 - uv.x) * aspect, 1.0 - uv.y,
    (1.0 - params.mouse.x) * aspect, 1.0 - params.mouse.y, 5.8);
  light += windowLight(uv.y, 1.0 - uv.x, params.mouse.y, 1.0 - params.mouse.x, 3.1);
  light += windowLight(1.0 - uv.y, uv.x, 1.0 - params.mouse.y, params.mouse.x, 8.3);

  // Screen compositing preserves the dark center without alpha seams.
  let mapped = vec3f(1.0) - exp(-light * 1.35);
  let grain = (hash(position.xy + vec2f(fract(params.time) * 97.0)) - 0.5) / 255.0;
  return vec4f(max(mapped + grain, vec3f(0.0)), 1.0);
}
