<script setup>
import Hero from "./Hero.vue";
import IcliShowcase from "./IcliShowcase.vue";
import FeatureToolbar from "./FeatureToolbar.vue";
import FeatureLinter from "./FeatureLinter.vue";
import FeatureFormatter from "./FeatureFormatter.vue";
import FeatureParser from "./FeatureParser.vue";
import FeatureResolver from "./FeatureResolver.vue";
import FeatureTransformer from "./FeatureTransformer.vue";
import FeatureMinifier from "./FeatureMinifier.vue";
import { sponsors } from "./sponsors";
import HeadingSection from "@voidzero-dev/vitepress-theme/src/components/oss/HeadingSection.vue";
import Sponsors from "@voidzero-dev/vitepress-theme/src/components/oss/Sponsors.vue";
import Footer from "@voidzero-dev/vitepress-theme/src/components/oss/Footer.vue";
</script>

<template>
  <Hero />
  <IcliShowcase />
  <HeadingSection heading="AI is cheap when given the best tools for the job" />
  <section id="features">
    <FeatureToolbar />
    <FeatureLinter />
    <FeatureFormatter />
    <FeatureParser />
    <FeatureTransformer />
    <FeatureResolver />
    <FeatureMinifier />
  </section>
  <Sponsors
    description="managing.software is free and open source, made possible by its community."
    sponsorLink="/sponsor"
    :sponsors="sponsors"
    :side-by-side-tiers="['Bronze Sponsors', 'Backers']"
    logo-style="opencollective"
  />
  <Footer
    heading="Explore the managing.software ecosystem"
    subheading="Tools for managing your digital life, starting with iCloud Calendar, Mail, and Contacts."
    button-text="Read the iCloud CLI guide"
    button-link="/docs/guide/usage/icloud-cli"
  />
</template>
