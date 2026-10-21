import "virtual:group-icons.css";
import type { Theme } from "vitepress";
import { VoidZeroTheme, themeContextKey } from "@voidzero-dev/vitepress-theme/src";
import AppBlogPostHeader from "./components/AppBlogPostHeader.vue";
import AppBlogList from "./components/AppBlogList.vue";
import RulesTable from "./components/RulesTable.vue";
import RuleHeader from "./components/RuleHeader.vue";
import RuleReferences from "./components/RuleReferences.vue";
import Alert from "./components/Alert.vue";
import CompatibilityMatrix from "./components/CompatibilityMatrix.vue";
import "./styles.css";

export default {
  ...VoidZeroTheme,
  async enhanceApp(ctx) {
    const { app } = ctx;
    app.provide(themeContextKey, {
      logoDark: "/managing-wordmark-dark.svg",
      logoLight: "/managing-wordmark-light.svg",
      logoAlt: "managing.software",
      footerBg: "",
      monoIcon: "/managing-logo.svg",
    });
    VoidZeroTheme.enhanceApp?.(ctx);
    app.component("Alert", Alert);
    app.component("CompatibilityMatrix", CompatibilityMatrix);
    app.component("AppBlogPostHeader", AppBlogPostHeader);
    app.component("AppBlogList", AppBlogList);
    app.component("RulesTable", RulesTable);
    app.component("RuleHeader", RuleHeader);
    app.component("RuleReferences", RuleReferences);
  },
} satisfies Theme;
