<script setup>
import TerminalDemo from "./TerminalDemo.vue";

const methods = [
  { name: "iCLI only", color: "#74d9bd" },
  { name: "scripting + pycloud", color: "#7b9cf7" },
  { name: "browser use", color: "#d69df6" },
  { name: "no guidance", color: "#f2ba71" },
];

const measures = ["Average tokens", "Average time", "Average failures", "Average steps"];
</script>

<template>
  <section
    id="icli-showcase"
    class="showcase wrapper border-t"
    aria-label="iCLI benchmark and demo"
  >
    <div class="showcase-grid grid border-y border-white/10 lg:grid-cols-2">
      <div class="benchmark-panel px-5 py-7 sm:px-8 md:py-9" aria-labelledby="benchmark-title">
        <div class="flex items-start justify-between gap-4">
          <div>
            <h3 id="benchmark-title" class="text-white">Compare the whole task</h3>
            <p class="mt-2 max-w-[28rem] text-sm leading-relaxed text-white/55">
              Compare four ways to migrate a full Google Calendar. Results will appear here when the
              runs are complete.
            </p>
          </div>
          <span class="tooltip-wrap relative shrink-0">
            <button
              type="button"
              class="info-button grid size-8 place-items-center rounded-full text-white/65 hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-aqua"
              aria-label="About the no-guidance comparison"
              aria-describedby="no-guidance-tip"
            >
              <svg viewBox="0 0 20 20" fill="none" aria-hidden="true" class="size-[18px]">
                <circle cx="10" cy="10" r="7.25" stroke="currentColor" stroke-width="1.5" />
                <path
                  d="M10 9v4m0-6h.01"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-linecap="round"
                />
              </svg>
            </button>
            <span id="no-guidance-tip" role="tooltip" class="tooltip">
              No guidance means we did not instruct our agent on what to use. We tested all frontier
              models. This is how well they did without iCLI to migrate our Google Calendar in its
              entirety.
            </span>
          </span>
        </div>

        <div
          class="measure-legend mt-6 flex flex-wrap gap-x-4 gap-y-2"
          aria-label="Comparison methods"
        >
          <span
            v-for="method in methods"
            :key="method.name"
            class="flex items-center gap-2 text-[11px] text-white/55"
          >
            <i class="size-2 rounded-sm" :style="{ backgroundColor: method.color }"></i>
            {{ method.name }}
          </span>
        </div>

        <div class="measure-grid mt-6 grid grid-cols-2" aria-label="Benchmark results pending">
          <div v-for="measure in measures" :key="measure" class="measure-group min-w-0">
            <h4 class="min-h-10 break-words text-xs leading-snug text-white/65">{{ measure }}</h4>
            <div class="bar-field" aria-hidden="true">
              <div v-for="method in methods" :key="method.name" class="bar-slot">
                <span :style="{ '--bar-color': method.color }"></span>
              </div>
            </div>
            <p class="mt-2 text-[10px] text-white/35">Pending</p>
          </div>
        </div>
        <p class="mt-5 text-xs leading-relaxed text-white/40">
          Same task and account for each method. No token, time, failure, or step results have been
          published yet.
        </p>
      </div>

      <div
        class="preview-panel relative overflow-hidden border-t border-white/10 px-5 py-7 sm:px-8 md:py-9 lg:border-l lg:border-t-0"
      >
        <div class="new-ribbon" aria-label="New preview">NEW</div>
        <div class="mb-5 pr-12">
          <h3 class="text-white">A conversation, then a command.</h3>
          <p class="mt-2 text-sm leading-relaxed text-white/55">
            Your agent uses iCLI to do the task and leaves the email as a draft.
          </p>
        </div>
        <TerminalDemo class="w-full" />
      </div>
    </div>
  </section>
</template>

<style scoped>
.showcase h2 {
  font-size: clamp(2rem, 4.2vw, 3.5rem);
  letter-spacing: -0.05em;
  line-height: 1.02;
}

.measure-grid {
  margin-right: -1.25rem;
  margin-left: -1.25rem;
  border-top: 1px solid rgb(255 255 255 / 13%);
  border-left: 1px solid rgb(255 255 255 / 13%);
}

.measure-group {
  min-width: 0;
  padding: 0.75rem;
  border-right: 1px solid rgb(255 255 255 / 13%);
  border-bottom: 1px solid rgb(255 255 255 / 13%);
}

.bar-field {
  display: flex;
  height: 9rem;
  align-items: end;
  gap: 0.3rem;
  padding: 0 0.15rem 0.4rem;
  background: repeating-linear-gradient(
    to top,
    transparent 0,
    transparent 1.95rem,
    rgb(255 255 255 / 5%) 2rem
  );
}

.bar-slot {
  display: flex;
  height: 100%;
  flex: 1;
  align-items: end;
  justify-content: center;
}

.bar-slot span {
  width: 100%;
  height: 88%;
  border: 1px dashed color-mix(in srgb, var(--bar-color), transparent 35%);
  border-radius: 2px 2px 0 0;
  background: repeating-linear-gradient(
    135deg,
    color-mix(in srgb, var(--bar-color), transparent 76%) 0 1px,
    transparent 1px 5px
  );
}

@media (min-width: 640px) {
  .measure-grid {
    margin-right: -2rem;
    margin-left: -2rem;
  }
}

.new-ribbon {
  position: absolute;
  top: 1.15rem;
  right: -2.3rem;
  z-index: 1;
  width: 8rem;
  transform: rotate(45deg);
  background: #75dfc5;
  padding: 0.35rem 0;
  color: #0e2520;
  text-align: center;
  font:
    700 0.62rem/1 ui-monospace,
    SFMono-Regular,
    Consolas,
    monospace;
  letter-spacing: 0.12em;
}

.tooltip {
  position: absolute;
  z-index: 10;
  top: calc(100% + 0.5rem);
  right: 0;
  width: min(18rem, calc(100vw - 3rem));
  border: 1px solid rgb(255 255 255 / 14%);
  border-radius: 0.65rem;
  background: #171b1b;
  padding: 0.75rem;
  color: rgb(255 255 255 / 78%);
  font-size: 0.72rem;
  line-height: 1.55;
  box-shadow: 0 12px 30px rgb(0 0 0 / 30%);
  opacity: 0;
  pointer-events: none;
  transform: translateY(-3px);
  transition:
    opacity 140ms ease,
    transform 140ms ease;
}

.tooltip-wrap:hover .tooltip,
.tooltip-wrap:focus-within .tooltip {
  opacity: 1;
  transform: translateY(0);
}

@media (prefers-reduced-motion: reduce) {
  .tooltip {
    transition: none;
  }
}
</style>
