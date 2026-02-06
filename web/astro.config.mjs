// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

import tailwindcss from '@tailwindcss/vite';

// https://astro.build/config
export default defineConfig({
  site: 'https://pkgwatch.dev',
  compressHTML: true,
  integrations: [sitemap({
    filter: (page) =>
      !page.includes('/dashboard') &&
      !page.includes('/login') &&
      !page.includes('/signup') &&
      !page.includes('/recover')
  })],
  vite: {
    plugins: [tailwindcss()]
  }
});