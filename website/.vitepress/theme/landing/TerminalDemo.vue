<script setup>
import { onBeforeUnmount, onMounted, ref } from "vue";

const userMessage =
  "Can you find next week's planning meeting, check who's invited, and draft a follow-up to Jordan?";
const assistantMessage = "Sure. I'll check the event and contact, then leave the draft unsent.";
const timestamp = ref("Loading time");

const formatDate = (date) => {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
};

const getSequence = () => {
  const monday = new Date();
  monday.setHours(12, 0, 0, 0);
  const daysUntilMonday = (8 - monday.getDay()) % 7 || 7;
  monday.setDate(monday.getDate() + daysUntilMonday);
  const sunday = new Date(monday);
  sunday.setDate(monday.getDate() + 6);

  return [
    {
      kind: "prompt",
      text: `icli calendar events list ${formatDate(monday)} ${formatDate(sunday)}`,
    },
    { kind: "out", text: "Planning sync - Wed 10:00 - Jordan, Casey", id: "evt-planning-01" },
    { kind: "reason", text: "Checking Jordan's contact for an email address..." },
    { kind: "prompt", text: "icli contacts list --limit 100" },
    { kind: "out", text: "Jordan Lee - jordan@example.test", id: "contact-jordan-01" },
    {
      kind: "prompt",
      text: 'icli mail create --to jordan@example.test --subject "Planning follow-up"',
    },
    { kind: "reason", text: "I'll save this as a draft so you can review it." },
    { kind: "detail", text: '--body "Thanks for meeting. I\'ll share notes this afternoon."' },
    { kind: "out", text: "Draft saved - not sent", id: "draft-followup-01", success: true },
  ];
};

const sequence = ref([]);
const rows = ref([]);
const prefersReducedMotion = ref(false);
const paused = ref(false);
const running = ref(false);
const currentStep = ref(0);
let timer = null;
let remaining = 800;
let dueAt = 0;
let motionQuery;

const clearTimer = () => {
  if (timer) clearTimeout(timer);
  timer = null;
};

const schedule = (delay, callback = advance) => {
  clearTimer();
  remaining = delay;
  dueAt = Date.now() + delay;
  timer = setTimeout(() => {
    timer = null;
    callback();
  }, delay);
};

const start = () => {
  sequence.value = getSequence();
  rows.value = [{ ...sequence.value[0], key: 0 }];
  currentStep.value = 1;
  paused.value = false;
  running.value = true;
  schedule(1100);
};

const advance = () => {
  if (prefersReducedMotion.value || paused.value) return;
  const entry = sequence.value[currentStep.value];
  if (!entry) {
    running.value = false;
    schedule(2600, start);
    return;
  }
  rows.value.push({ ...entry, key: currentStep.value });
  currentStep.value += 1;
  schedule(entry.kind === "out" ? 1100 : 850);
};

const togglePlayback = () => {
  if (prefersReducedMotion.value) return;
  if (paused.value) {
    paused.value = false;
    if (running.value) schedule(remaining);
    else start();
    return;
  }
  if (timer) remaining = Math.max(0, dueAt - Date.now());
  clearTimer();
  paused.value = true;
};

const replay = () => {
  if (!prefersReducedMotion.value) start();
};

const updateMotionPreference = () => {
  prefersReducedMotion.value = motionQuery?.matches ?? false;
  if (prefersReducedMotion.value) {
    clearTimer();
    sequence.value = getSequence();
    rows.value = sequence.value.map((entry, key) => ({ ...entry, key }));
    currentStep.value = sequence.value.length;
    running.value = false;
    paused.value = false;
  } else if (!running.value) {
    start();
  }
};

onMounted(() => {
  timestamp.value = new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date());
  motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  motionQuery.addEventListener?.("change", updateMotionPreference);
  updateMotionPreference();
});

onBeforeUnmount(() => {
  clearTimer();
  motionQuery?.removeEventListener?.("change", updateMotionPreference);
});
</script>

<template>
  <div class="demo-flow w-full max-w-[42rem]">
    <div class="mb-4 flex flex-col gap-3" aria-label="Sample conversation">
      <div class="flex flex-col items-start gap-1.5">
        <p class="flex items-center gap-2 text-[11px] text-white/45">
          <span
            class="grid size-5 place-items-center rounded-full bg-white/10 font-mono text-white/75"
            >U</span
          >
          <span>{{ timestamp }}</span>
        </p>
        <p
          class="max-w-[94%] rounded-2xl rounded-bl-sm border border-white/10 bg-white/[0.06] px-4 py-3 text-sm leading-relaxed text-white/90 sm:text-base"
        >
          &ldquo;{{ userMessage }}&rdquo;
        </p>
      </div>

      <div class="flex justify-end">
        <div class="agent-bubble w-full min-w-0 rounded-2xl rounded-br-sm p-3 sm:p-4">
          <p class="mb-2 text-right text-[11px] text-blue-100/65">Your agent with access to iCLI</p>
          <p class="mb-3 text-right text-sm leading-relaxed text-blue-50 sm:text-base">
            {{ assistantMessage }}
          </p>
          <div
            class="overflow-hidden rounded-xl border border-white/10 bg-[#171b1b] shadow-xl shadow-black/20"
            role="group"
            aria-label="Sample iCLI terminal transcript"
          >
            <div
              class="flex items-center gap-2 border-b border-white/10 bg-white/[0.035] px-3 py-2.5 sm:px-4 sm:py-3"
            >
              <span class="size-2 rounded-full bg-[#ed766b]"></span>
              <span class="size-2 rounded-full bg-[#e9bf60]"></span>
              <span class="size-2 rounded-full bg-[#79bf83]"></span>
              <span
                class="ml-1 hidden whitespace-nowrap font-mono text-[11px] tracking-wide text-white/40 sm:inline"
                >icli - sample account</span
              >
              <div class="ml-auto flex items-center gap-1">
                <button
                  v-if="!prefersReducedMotion"
                  type="button"
                  class="demo-control"
                  :aria-label="paused ? 'Resume sample' : 'Pause sample'"
                  :aria-pressed="paused"
                  :title="paused ? 'Resume sample' : 'Pause sample'"
                  @click="togglePlayback"
                >
                  <svg
                    v-if="paused"
                    viewBox="0 0 20 20"
                    fill="currentColor"
                    aria-hidden="true"
                    class="size-4"
                  >
                    <path
                      d="M6 4.8a.8.8 0 0 1 1.22-.68l7.2 4.4a1.72 1.72 0 0 1 0 2.94l-7.2 4.4A.8.8 0 0 1 6 15.18V4.8Z"
                    />
                  </svg>
                  <svg
                    v-else
                    viewBox="0 0 20 20"
                    fill="currentColor"
                    aria-hidden="true"
                    class="size-4"
                  >
                    <path
                      d="M5.75 4.5A1.25 1.25 0 0 1 7 5.75v8.5a1.25 1.25 0 1 1-2.5 0v-8.5A1.25 1.25 0 0 1 5.75 4.5Zm8.5 0a1.25 1.25 0 0 1 1.25 1.25v8.5a1.25 1.25 0 1 1-2.5 0v-8.5a1.25 1.25 0 0 1 1.25-1.25Z"
                    />
                  </svg>
                </button>
                <button
                  v-if="!prefersReducedMotion"
                  type="button"
                  class="demo-control"
                  aria-label="Replay sample"
                  title="Replay sample"
                  @click="replay"
                >
                  <svg viewBox="0 0 20 20" fill="none" aria-hidden="true" class="size-4">
                    <path
                      d="M4 9a6 6 0 1 1 1.8 4.28M4 5.5V9h3.5"
                      stroke="currentColor"
                      stroke-width="1.6"
                      stroke-linecap="round"
                      stroke-linejoin="round"
                    />
                  </svg>
                </button>
              </div>
            </div>

            <div
              class="min-h-[17rem] space-y-1.5 px-3 py-4 text-left font-mono text-[11px] leading-relaxed sm:min-h-[18rem] sm:px-5 sm:text-xs"
            >
              <div v-for="row in rows" :key="row.key" class="demo-row">
                <div v-if="row.kind === 'prompt'" class="flex items-start gap-2 text-white/90">
                  <span class="shrink-0 text-aqua">$</span
                  ><span class="break-words">{{ row.text }}</span>
                </div>
                <div v-else-if="row.kind === 'reason'" class="break-words pl-4 text-aqua/70 italic">
                  {{ row.text }}
                </div>
                <div v-else-if="row.kind === 'detail'" class="break-words pl-4 text-white/65">
                  {{ row.text }}
                </div>
                <div v-else class="flex items-start gap-2 pl-4 text-white/65">
                  <span class="shrink-0" :class="row.success ? 'text-aqua' : 'text-white/30'">{{
                    row.success ? "✓" : "↳"
                  }}</span>
                  <span class="min-w-0 break-words">{{ row.text }}</span>
                  <span
                    v-if="row.id"
                    class="ml-auto hidden shrink-0 whitespace-nowrap text-white/30 sm:inline"
                    >{{ row.id }}</span
                  >
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.demo-control {
  display: grid;
  width: 2rem;
  height: 2rem;
  place-items: center;
  border-radius: 999px;
  color: rgb(255 255 255 / 58%);
  transition:
    color 150ms ease,
    background-color 150ms ease;
}

.agent-bubble {
  border: 1px solid rgb(96 165 250 / 28%);
  background: rgb(37 99 235 / 24%);
}

.demo-control:hover {
  color: #fff;
  background: rgb(255 255 255 / 7%);
}

.demo-control:focus-visible {
  outline: 2px solid #75dfc5;
  outline-offset: 2px;
}

.demo-row {
  animation: reveal 280ms ease both;
}

@keyframes reveal {
  from {
    opacity: 0;
    transform: translateY(4px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@media (prefers-reduced-motion: reduce) {
  .demo-row {
    animation: none;
  }
  .demo-control {
    transition: none;
  }
}
</style>
