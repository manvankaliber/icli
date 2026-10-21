<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from "vue";
import type { Effect, Gpu, Surface } from "vgpu";
import { clock, effect, frameLoop, init, surface } from "vgpu";
import lightShader from "./hero-rainbow-light.wgsl";

const canvas = ref<HTMLCanvasElement>();
let gpu: Gpu | undefined;
let canvasSurface: Surface | undefined;
let lightEffect: Effect | undefined;
let loop: ReturnType<typeof frameLoop> | undefined;
let resizeObserver: ResizeObserver | undefined;
let reducedMotion: MediaQueryList | undefined;
let mouse = [0.5, 0.5];
let targetMouse = [0.5, 0.5];
let activity = 0;
let targetActivity = 0;
let momentum = [0, 0];
let lastPointerTime = 0;
let lastFrameTime = 0;

function setUniforms(time = 0) {
  if (!lightEffect || !canvas.value) return;
  lightEffect.set({
    params: {
      time,
      activity,
      resolution: [canvas.value.width, canvas.value.height],
      mouse,
      momentum,
    },
  });
}

function movePointer(event: PointerEvent) {
  const bounds = canvas.value?.getBoundingClientRect();
  if (!bounds) return;
  const nextMouse = [
    Math.max(0, Math.min(1, (event.clientX - bounds.left) / bounds.width)),
    Math.max(0, Math.min(1, (event.clientY - bounds.top) / bounds.height)),
  ];
  const now = performance.now();
  const elapsed = lastPointerTime
    ? Math.min(Math.max((now - lastPointerTime) / 1000, 0.016), 0.08)
    : 0.016;
  const delta = [nextMouse[0] - targetMouse[0], nextMouse[1] - targetMouse[1]];
  const distance = Math.hypot(delta[0], delta[1]);
  if (distance > 0) {
    const speed = distance / elapsed;
    const impulse = Math.min(speed * 0.12, 0.12);
    momentum = [
      momentum[0] * 0.58 + (delta[0] / distance) * impulse,
      momentum[1] * 0.58 + (delta[1] / distance) * impulse,
    ];
  }
  targetMouse = nextMouse;
  targetActivity = 1;
  lastPointerTime = now;
  if (reducedMotion?.matches && lightEffect && canvasSurface) {
    mouse = targetMouse;
    activity = 1;
    setUniforms();
    lightEffect.draw(canvasSurface);
  }
}

function leavePointer() {
  targetActivity = 0;
  lastPointerTime = 0;
  if (reducedMotion?.matches && lightEffect && canvasSurface) {
    activity = 0;
    setUniforms();
    lightEffect.draw(canvasSurface);
  }
}

onMounted(async () => {
  const element = canvas.value;
  if (!element) return;

  reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  try {
    gpu = await init({ powerPreference: "low-power", label: "Homepage rainbow light" });
    if (!canvas.value) {
      gpu.dispose();
      return;
    }

    canvasSurface = surface(gpu, element, {
      alphaMode: "premultiplied",
      clearColor: [0, 0, 0, 0],
      dpr: [1, 1.25],
      label: "Homepage light canvas",
    });
    lightEffect = effect(gpu, lightShader, {
      blend: "alpha",
      label: "Mouse-reactive rainbow light",
    });
    const timer = clock(gpu);
    setUniforms();
    await lightEffect.compile(canvasSurface);
    if (!canvas.value) return;
    lastFrameTime = performance.now();

    if (reducedMotion.matches) {
      lightEffect.draw(canvasSurface);
    } else {
      loop = frameLoop(
        gpu,
        (frame) => {
          const now = performance.now();
          const deltaTime = Math.min((now - lastFrameTime) / 1000, 0.05);
          lastFrameTime = now;
          const momentumDecay = Math.exp(-deltaTime * 1.7);
          momentum = [momentum[0] * momentumDecay, momentum[1] * momentumDecay];
          const follow = 1 - Math.exp(-deltaTime * 8);
          mouse = [
            mouse[0] + (targetMouse[0] - mouse[0]) * follow,
            mouse[1] + (targetMouse[1] - mouse[1]) * follow,
          ];
          activity += (targetActivity - activity) * (1 - Math.exp(-deltaTime * 3.5));
          setUniforms(timer.time);
          frame.pass(canvasSurface!, lightEffect!);
        },
        { fps: 45 },
      );
    }

    resizeObserver = new ResizeObserver(() => {
      if (!canvas.value || !lightEffect || !canvasSurface) return;
      setUniforms(timer.time);
      if (reducedMotion?.matches) lightEffect.draw(canvasSurface);
    });
    resizeObserver.observe(element);
  } catch (error) {
    if (import.meta.env.DEV) {
      const cause = (error as { cause?: { message?: string } })?.cause;
      console.warn(
        "Hero light unavailable",
        error instanceof Error ? error.message : error,
        cause?.message ?? "",
      );
    }
    // Keep the static CSS glow as a graceful fallback where WebGPU is unavailable.
    gpu?.dispose();
    gpu = undefined;
  }
});

onBeforeUnmount(() => {
  resizeObserver?.disconnect();
  loop?.stop();
  gpu?.dispose();
});
</script>

<template>
  <section
    class="hero wrapper wrapper--ticks relative isolate w-full overflow-hidden border-nickel"
    aria-labelledby="home-title"
    @pointermove="movePointer"
    @pointerleave="leavePointer"
  >
    <div class="light-fallback" aria-hidden="true"></div>
    <canvas ref="canvas" class="light-canvas" aria-hidden="true"></canvas>
    <div
      class="hero-copy relative z-10 mx-auto max-w-[74rem] px-5 py-16 text-center sm:px-10 sm:py-24"
    >
      <span class="mb-5 inline-block font-mono text-xs tracking-wide text-aqua"
        >managing.software</span
      >
      <h1 id="home-title" class="max-w-[40rem] text-pretty text-white">
        We make tools for agents first.
      </h1>
      <p
        class="mx-auto mt-6 max-w-[38rem] text-pretty text-lg leading-relaxed text-white/70 sm:text-xl"
      >
        Our tools save supremely intelligent agents massive amounts of guesswork, research, and
        troubleshooting. Start saving tokens, time, and other resources today.
      </p>
      <div class="mt-9 flex flex-wrap items-center justify-center gap-4">
        <a href="#features" class="button button--primary inline-block w-fit">Explore our tools</a>
        <a href="/docs/guide/usage/icloud-cli" class="button inline-block w-fit">More about iCLI</a>
      </div>
    </div>
  </section>
  <aside class="announcement wrapper" aria-label="iCLI release announcement">
    <div class="announcement-texture" aria-hidden="true"></div>
    <div class="announcement-content">
      <strong>iCLI</strong>
      <span class="announcement-dash" aria-hidden="true">-</span>
      <span class="announcement-copy"
        >World's agent-first iCloud CLI <span class="announcement-launch">is OUT NOW!</span></span
      >
      <a
        href="/docs/guide/usage/icloud-cli"
        class="announcement-link"
        aria-label="Get started with iCLI"
      >
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M5 12h14m-6-6 6 6-6 6" />
        </svg>
      </a>
    </div>
  </aside>
</template>

<style scoped>
.hero {
  min-height: 34rem;
  display: grid;
  align-items: center;
  background:
    radial-gradient(ellipse 48% 56% at 50% 48%, rgb(20 72 106 / 15%), transparent 76%),
    var(--vp-c-bg);
}

.light-canvas,
.light-fallback {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
}

.light-canvas {
  z-index: 1;
  opacity: 0.9;
  mix-blend-mode: screen;
}

.light-fallback {
  z-index: 0;
  background:
    radial-gradient(ellipse 26% 72% at 0% 50%, rgb(255 75 48 / 8%), transparent 100%),
    radial-gradient(ellipse 26% 72% at 100% 50%, rgb(46 111 255 / 8%), transparent 100%),
    radial-gradient(ellipse 70% 28% at 50% 0%, rgb(255 202 48 / 7%), transparent 100%),
    radial-gradient(ellipse 70% 28% at 50% 100%, rgb(46 111 255 / 7%), transparent 100%);
}

.hero-copy {
  width: 100%;
}

.hero h1 {
  margin-inline: auto;
  font-size: clamp(3rem, 7vw, 6rem);
  line-height: 0.98;
  letter-spacing: -0.065em;
  text-shadow: 0 2px 26px var(--vp-c-bg);
}

.hero p {
  max-width: 44rem;
  text-shadow: 0 1px 18px var(--vp-c-bg);
}

.announcement {
  position: relative;
  isolation: isolate;
  width: 100%;
  min-height: 8.25rem;
  overflow: visible;
  background:
    radial-gradient(ellipse at 68% 125%, #f55c38 0%, transparent 65%),
    linear-gradient(105deg, #a92326, #d93831 42%, #bf2b2c);
  color: #fff4e8;
  box-shadow:
    0 -18px 70px -34px rgb(235 63 40 / 55%),
    0 22px 65px -35px rgb(235 63 40 / 40%);
}

.announcement-texture {
  position: absolute;
  z-index: 0;
  inset: 0;
  pointer-events: none;
  overflow: hidden;
  background:
    repeating-linear-gradient(
      176deg,
      transparent 0 8px,
      rgb(85 11 16 / 14%) 8px 9px,
      transparent 9px 24px
    ),
    repeating-linear-gradient(
      3deg,
      transparent 0 22px,
      rgb(91 13 17 / 13%) 22px 23px,
      transparent 23px 47px
    );
}

.announcement-texture::before,
.announcement-texture::after {
  position: absolute;
  inset: 9px 0;
  content: "";
  border-block: 1px dashed rgb(88 12 16 / 45%);
}

.announcement-texture::after {
  inset: 0;
  border: 0;
  opacity: 0.2;
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.74' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Cpath fill='%23000' filter='url(%23n)' opacity='.7' d='M0 0h200v200H0z'/%3E%3C/svg%3E");
  mix-blend-mode: multiply;
}

.announcement-content {
  position: relative;
  z-index: 1;
  display: flex;
  min-height: inherit;
  align-items: center;
  gap: clamp(1rem, 2.5vw, 2.5rem);
  padding: 1.5rem clamp(1.5rem, 5vw, 5rem);
}

.announcement strong {
  flex-shrink: 0;
  font-size: clamp(3rem, 5vw, 4.75rem);
  font-weight: 650;
  letter-spacing: -0.065em;
  line-height: 1;
}

.announcement-dash {
  font-size: 2rem;
  font-weight: 300;
  opacity: 0.5;
}

.announcement-copy {
  min-width: 0;
  font-size: clamp(1rem, 1.7vw, 1.5rem);
  font-weight: 500;
  line-height: 1.4;
  letter-spacing: -0.025em;
  text-wrap: balance;
}

.announcement-launch {
  white-space: nowrap;
}

.announcement-link {
  display: grid;
  width: 3rem;
  height: 3rem;
  margin-left: auto;
  flex-shrink: 0;
  place-items: center;
  border: 1px solid rgb(255 244 232 / 45%);
  border-radius: 50%;
  transition:
    background 180ms ease,
    color 180ms ease;
}

.announcement-link:hover {
  background: #fff4e8;
  color: #b32826;
}

.announcement-link:focus-visible {
  outline: 2px solid currentColor;
  outline-offset: 5px;
}

.announcement-link svg {
  width: 1.35rem;
  stroke: currentColor;
  stroke-width: 1.5;
  stroke-linecap: round;
  stroke-linejoin: round;
}

@media (max-width: 520px) {
  .announcement {
    min-height: 7rem;
  }

  .announcement-content {
    gap: 0.85rem;
    padding: 1.35rem 1.25rem;
  }

  .announcement-dash {
    display: none;
  }

  .announcement-link {
    width: 2.25rem;
    height: 2.25rem;
  }

  .announcement-copy {
    font-size: 0.9rem;
  }
}

@media (prefers-reduced-motion: reduce) {
  .light-canvas {
    opacity: 0.75;
  }
}
</style>
