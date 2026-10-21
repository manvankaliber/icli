<template>
  <section id="feature-parser" class="wrapper grid border-t md:grid-cols-2">
    <div class="flex flex-col justify-center gap-5 px-5 py-8 md:p-10 md:py-15">
      <span class="font-mono text-xs tracking-wide text-aqua">iCLI · iCloud for your agent</span>
      <h2 class="text-white">Calendar, contacts, and mail in one CLI.</h2>
      <p class="max-w-[28rem] text-pretty text-base leading-relaxed text-white/70">
        Give your agent direct commands for everyday iCloud tasks. iCLI returns stable IDs,
        structured results, and helpful next steps.
      </p>
      <a href="/docs/guide/usage/icloud-cli" class="button mt-2 w-fit">Read the iCLI guide</a>
    </div>

    <div
      class="flex flex-col justify-center border-t border-white/10 px-5 py-8 md:border-l md:border-t-0 md:px-10 md:py-12"
    >
      <dl class="feature-details grid grid-cols-2 border-l border-t border-white/10">
        <div class="min-w-0 border-b border-r border-white/10 p-3 sm:p-5">
          <dt class="font-mono text-xs tracking-wide text-aqua">CALENDAR</dt>
          <dd class="mt-2 break-words text-sm leading-relaxed text-white/65">
            Find events, check details, and manage schedules.
          </dd>
        </div>
        <div class="min-w-0 border-b border-r border-white/10 p-3 sm:p-5">
          <dt class="font-mono text-xs tracking-wide text-aqua">CONTACTS</dt>
          <dd class="mt-2 break-words text-sm leading-relaxed text-white/65">
            Look up people and the details your agent needs.
          </dd>
        </div>
        <div class="min-w-0 border-b border-r border-white/10 p-3 sm:p-5">
          <dt class="font-mono text-xs tracking-wide text-aqua">MAIL</dt>
          <dd class="mt-2 break-words text-sm leading-relaxed text-white/65">
            Search messages and prepare drafts for review.
          </dd>
        </div>
        <div class="min-w-0 border-b border-r border-white/10 p-3 sm:p-5">
          <dt class="font-mono text-xs tracking-wide text-aqua">AGENT OUTPUT</dt>
          <dd class="mt-2 break-words text-sm leading-relaxed text-white/65">
            Readable responses, JSON, CSV, and actionable errors.
          </dd>
        </div>
      </dl>
    </div>
  </section>
</template>
