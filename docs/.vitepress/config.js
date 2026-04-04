import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'GreenGate',
  description: 'Rust DevOps CLI: supply-chain protection, secret scanning, AST-based SAST, Kubernetes linting, coverage gates, dependency auditing, and web performance — single zero-dependency binary.',
  base: '/greengate/',

  head: [
    ['meta', { name: 'og:title', content: 'GreenGate — Rust DevOps CLI' }],
    ['meta', { name: 'og:description', content: 'Secret scanning, SAST, Kubernetes linting, coverage gates, dependency auditing in a single Rust binary.' }],
    ['meta', { name: 'og:type', content: 'website' }],
    ['link', { rel: 'icon', href: '/greengate/favicon.ico' }],
  ],

  themeConfig: {
    logo: null,
    siteTitle: 'GreenGate',

    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'Commands', link: '/commands/scan' },
      { text: 'Reference', link: '/reference/config' },
      { text: 'GitHub', link: 'https://github.com/ThinkGrid-Labs/greengate' },
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
          { text: '🔒 watch-install', link: '/commands/watch-install' },
          { text: 'scan', link: '/commands/scan' },
          { text: 'audit', link: '/commands/audit' },
          { text: 'lint', link: '/commands/lint' },
          { text: 'docker-lint', link: '/commands/docker-lint' },
          { text: 'coverage', link: '/commands/coverage' },
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
          { text: 'Roadmap', link: '/reference/roadmap' },
        ],
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/ThinkGrid-Labs/greengate' },
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © ThinkGrid Labs',
    },

    search: {
      provider: 'local',
    },

    editLink: {
      pattern: 'https://github.com/ThinkGrid-Labs/greengate/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },
  },
})
