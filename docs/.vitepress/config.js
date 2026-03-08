import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'OxideCI',
  description: 'Rust DevOps CLI: secret scanning, AST-based SAST, Kubernetes linting, coverage gates, dependency auditing, and web performance — single zero-dependency binary.',
  base: '/oxide-ci/',

  head: [
    ['meta', { name: 'og:title', content: 'OxideCI — Rust DevOps CLI' }],
    ['meta', { name: 'og:description', content: 'Secret scanning, SAST, Kubernetes linting, coverage gates, dependency auditing in a single Rust binary.' }],
    ['meta', { name: 'og:type', content: 'website' }],
    ['link', { rel: 'icon', href: '/oxide-ci/favicon.ico' }],
  ],

  themeConfig: {
    logo: null,
    siteTitle: 'OxideCI',

    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'Commands', link: '/commands/scan' },
      { text: 'Reference', link: '/reference/config' },
      { text: 'GitHub', link: 'https://github.com/ThinkGrid-Labs/oxide-ci' },
    ],

    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Getting Started', link: '/guide/getting-started' },
          { text: 'CI/CD Integration', link: '/guide/ci-integration' },
          { text: 'Use Cases & Scenarios', link: '/guide/use-cases' },
          { text: 'Configuration File', link: '/reference/config' },
        ],
      },
      {
        text: 'Commands',
        items: [
          { text: 'scan', link: '/commands/scan' },
          { text: 'lint', link: '/commands/lint' },
          { text: 'docker-lint', link: '/commands/docker-lint' },
          { text: 'coverage', link: '/commands/coverage' },
          { text: 'audit', link: '/commands/audit' },
          { text: 'install-hooks', link: '/commands/install-hooks' },
          { text: 'lighthouse', link: '/commands/lighthouse' },
          { text: 'reassure', link: '/commands/reassure' },
          { text: 'init', link: '/commands/init' },
          { text: 'watch', link: '/commands/watch' },
          { text: 'run', link: '/commands/run' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Secret Patterns', link: '/reference/secret-patterns' },
          { text: 'SAST Rules', link: '/reference/sast-rules' },
          { text: 'Exit Codes', link: '/reference/exit-codes' },
          { text: 'Output Formats', link: '/reference/output-formats' },
          { text: 'Limitations', link: '/reference/limitations' },
        ],
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/ThinkGrid-Labs/oxide-ci' },
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © ThinkGrid Labs',
    },

    search: {
      provider: 'local',
    },

    editLink: {
      pattern: 'https://github.com/ThinkGrid-Labs/oxide-ci/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },
  },
})
