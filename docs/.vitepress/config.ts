import { defineConfig } from 'vitepress'

// Project Pages site served at https://aahan-pat.github.io/chaosify/ — the `base`
// must match the repo name or asset/links 404 in production.
export default defineConfig({
  title: 'Chaosify',
  description: 'Deterministic CLI for Kubernetes Continuous Control Verification',
  base: '/chaosify/',
  cleanUrls: true,
  lastUpdated: true,
  head: [['link', { rel: 'icon', href: '/chaosify/favicon.ico' }]],
  themeConfig: {
    nav: [
      { text: 'Reference', link: '/reference' },
      { text: 'Architecture', link: '/architecture' },
      { text: 'Scenarios', link: '/scenarios' },
      { text: 'npm', link: 'https://www.npmjs.com/package/chaosify-kubernetes' },
    ],
    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Overview', link: '/' },
          { text: 'Architecture', link: '/architecture' },
          { text: 'Command Reference', link: '/reference' },
          { text: 'Scenarios', link: '/scenarios' },
        ],
      },
      {
        text: 'Deep dives',
        items: [
          { text: 'RBAC Command', link: '/rbac-command' },
          { text: 'Recon Summary Format', link: '/recon-summary-format' },
          { text: 'Accuracy Gaps (minikube)', link: '/accuracy-gaps-minikube' },
          { text: 'Case Study: Kubernetes Goat', link: '/case-study-kubernetes-goat' },
        ],
      },
      {
        text: 'Devlog',
        collapsed: true,
        items: [
          { text: '2026-06-11', link: '/devlog/2026-06-11' },
          { text: '2026-06-10', link: '/devlog/2026-06-10' },
        ],
      },
    ],
    socialLinks: [{ icon: 'github', link: 'https://github.com/aahan-pat/chaosify' }],
    search: { provider: 'local' },
    editLink: {
      pattern: 'https://github.com/aahan-pat/chaosify/edit/main/docs/:path',
    },
  },
})
