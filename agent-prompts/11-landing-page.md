# Agent Prompt: Landing Page Improvements

## Context

You are working on DepHealth, a dependency health intelligence platform. The landing page needs improvements for conversion, SEO, and user experience.

**Project Root:** `/home/iebt/projects/startup-experiment/work/dephealth/landing-page`
**Review Document:** `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` (Section 11: Landing Page Review)

## Your Mission

Improve the landing page for better conversion, SEO, accessibility, and user trust.

## Current Stack
- **Framework:** Astro
- **Hosting:** S3 + CloudFront (via Terraform)
- **Deployment:** `./deploy.sh`

## Critical Improvements

### 1. Add Self-Service API Signup (CRITICAL)

**Problem:** Current signup is email-based, creating massive friction.

**Current (CTA.astro:21):**
```astro
<a href="mailto:hello@laranjo.dev?subject=DepHealth API Key Request...">
  Get Free API Key
</a>
```

**Solution:** Create signup page with magic link authentication.

**Create:** `src/pages/signup.astro`
```astro
---
import Layout from '../layouts/Layout.astro';
import Navbar from '../components/Navbar.astro';
import Footer from '../components/Footer.astro';
---

<Layout title="Sign Up | DepHealth">
  <Navbar />

  <main class="max-w-md mx-auto px-4 py-24">
    <div class="text-center mb-8">
      <h1 class="text-3xl font-bold text-white mb-4">Get Your Free API Key</h1>
      <p class="text-zinc-400">
        Start with 5,000 free requests per month. No credit card required.
      </p>
    </div>

    <form id="signup-form" class="space-y-6">
      <div>
        <label for="email" class="block text-sm font-medium text-zinc-300 mb-2">
          Email Address
        </label>
        <input
          type="email"
          id="email"
          name="email"
          required
          class="w-full px-4 py-3 bg-[#0d0d10] border border-zinc-800 rounded-lg
                 text-white placeholder-zinc-500 focus:border-emerald-500
                 focus:ring-1 focus:ring-emerald-500 outline-none transition"
          placeholder="you@company.com"
        />
      </div>

      <button
        type="submit"
        class="w-full btn-gradient px-6 py-3 rounded-lg font-semibold
               text-white transition hover:opacity-90 disabled:opacity-50"
      >
        <span id="btn-text">Get API Key</span>
        <span id="btn-loading" class="hidden">Sending...</span>
      </button>

      <p id="error-message" class="text-red-400 text-sm hidden"></p>
      <p id="success-message" class="text-emerald-400 text-sm hidden"></p>
    </form>

    <div class="mt-8 text-center text-sm text-zinc-500">
      Already have an account?{' '}
      <a href="/login" class="text-emerald-400 hover:text-emerald-300">
        Sign in
      </a>
    </div>
  </main>

  <Footer />
</Layout>

<script>
  const form = document.getElementById('signup-form');
  const btnText = document.getElementById('btn-text');
  const btnLoading = document.getElementById('btn-loading');
  const errorMsg = document.getElementById('error-message');
  const successMsg = document.getElementById('success-message');

  form?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const email = (document.getElementById('email') as HTMLInputElement).value;

    // Show loading state
    btnText?.classList.add('hidden');
    btnLoading?.classList.remove('hidden');
    errorMsg?.classList.add('hidden');

    try {
      const response = await fetch('https://api.dephealth.laranjo.dev/v1/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });

      const data = await response.json();

      if (response.ok) {
        successMsg.textContent = 'Check your email for a verification link!';
        successMsg?.classList.remove('hidden');
        form.reset();
      } else {
        errorMsg.textContent = data.error?.message || 'Something went wrong';
        errorMsg?.classList.remove('hidden');
      }
    } catch (error) {
      errorMsg.textContent = 'Network error. Please try again.';
      errorMsg?.classList.remove('hidden');
    } finally {
      btnText?.classList.remove('hidden');
      btnLoading?.classList.add('hidden');
    }
  });
</script>
```

**Update CTA.astro:**
```astro
<a href="/signup" class="btn-gradient px-8 py-4 rounded-lg text-lg font-semibold">
  Get Free API Key
</a>
```

### 2. Add Analytics (HIGH PRIORITY)

**Location:** `src/layouts/Layout.astro`

**Add Plausible analytics (privacy-friendly):**
```astro
<head>
  <!-- ... existing head content ... -->

  <!-- Analytics -->
  <script
    defer
    data-domain="dephealth.laranjo.dev"
    src="https://plausible.io/js/script.js"
  ></script>

  <!-- Track outbound links -->
  <script
    defer
    data-domain="dephealth.laranjo.dev"
    src="https://plausible.io/js/script.outbound-links.js"
  ></script>
</head>
```

**Add event tracking for key actions:**
```astro
<!-- In LiveDemo.astro, track demo usage -->
<script>
  // After successful demo check
  if (window.plausible) {
    plausible('Demo Check', { props: { package: packageName } });
  }
</script>
```

### 3. Add SEO Elements (HIGH PRIORITY)

**Location:** `src/layouts/Layout.astro`

**Add missing meta tags:**
```astro
---
interface Props {
  title: string;
  description?: string;
  image?: string;
  canonical?: string;
}

const {
  title,
  description = "Predict which npm dependencies are at risk of abandonment. Get health scores and risk assessments for your packages.",
  image = "https://dephealth.laranjo.dev/og-image.png",
  canonical = Astro.url.href,
} = Astro.props;
---

<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />

    <!-- Primary Meta Tags -->
    <title>{title}</title>
    <meta name="title" content={title} />
    <meta name="description" content={description} />
    <link rel="canonical" href={canonical} />

    <!-- Open Graph / Facebook -->
    <meta property="og:type" content="website" />
    <meta property="og:url" content={canonical} />
    <meta property="og:title" content={title} />
    <meta property="og:description" content={description} />
    <meta property="og:image" content={image} />
    <meta property="og:site_name" content="DepHealth" />

    <!-- Twitter -->
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:url" content={canonical} />
    <meta name="twitter:title" content={title} />
    <meta name="twitter:description" content={description} />
    <meta name="twitter:image" content={image} />

    <!-- Robots -->
    <meta name="robots" content="index, follow" />

    <!-- Favicon -->
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />

    <!-- ... rest of head ... -->
  </head>
</html>
```

**Create:** `public/robots.txt`
```
User-agent: *
Allow: /

Sitemap: https://dephealth.laranjo.dev/sitemap.xml
```

**Create:** `public/sitemap.xml`
```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://dephealth.laranjo.dev/</loc>
    <lastmod>2026-01-08</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://dephealth.laranjo.dev/docs</loc>
    <lastmod>2026-01-08</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://dephealth.laranjo.dev/methodology</loc>
    <lastmod>2026-01-08</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://dephealth.laranjo.dev/pricing</loc>
    <lastmod>2026-01-08</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://dephealth.laranjo.dev/signup</loc>
    <lastmod>2026-01-08</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
</urlset>
```

**Create:** `public/og-image.png`
Create a 1200x630px image with:
- DepHealth logo
- Tagline: "Predict dependency abandonment risk"
- Dark gradient background matching site theme

### 4. Add Mobile Navigation (MEDIUM PRIORITY)

**Location:** `src/components/Navbar.astro`

**Add hamburger menu for mobile:**
```astro
---
// Navbar.astro
---

<nav class="fixed top-0 left-0 right-0 z-50 bg-[#09090b]/80 backdrop-blur-lg border-b border-zinc-800/50">
  <div class="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between">
    <!-- Logo -->
    <a href="/" class="flex items-center gap-2">
      <span class="text-xl font-bold text-white">DepHealth</span>
      <span class="px-2 py-0.5 text-xs bg-emerald-500/20 text-emerald-400 rounded-full">
        Live
      </span>
    </a>

    <!-- Desktop Navigation -->
    <div class="hidden md:flex items-center gap-6">
      <a href="/docs" class="text-sm text-zinc-400 hover:text-white transition-colors">
        Docs
      </a>
      <a href="/methodology" class="text-sm text-zinc-400 hover:text-white transition-colors">
        Methodology
      </a>
      <a href="/pricing" class="text-sm text-zinc-400 hover:text-white transition-colors">
        Pricing
      </a>
      <a href="#devtools" class="text-sm text-zinc-400 hover:text-white transition-colors">
        CLI
      </a>
      <a
        href="/signup"
        class="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-white text-sm font-medium rounded-lg transition"
      >
        Get API Key
      </a>
    </div>

    <!-- Mobile Menu Button -->
    <button
      id="mobile-menu-btn"
      class="md:hidden p-2 text-zinc-400 hover:text-white"
      aria-label="Toggle menu"
    >
      <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path
          id="menu-icon"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2"
          d="M4 6h16M4 12h16M4 18h16"
        />
        <path
          id="close-icon"
          class="hidden"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2"
          d="M6 18L18 6M6 6l12 12"
        />
      </svg>
    </button>
  </div>

  <!-- Mobile Menu -->
  <div
    id="mobile-menu"
    class="hidden md:hidden border-t border-zinc-800/50 bg-[#09090b]"
  >
    <div class="px-4 py-4 space-y-4">
      <a href="/docs" class="block text-zinc-400 hover:text-white transition-colors">
        Docs
      </a>
      <a href="/methodology" class="block text-zinc-400 hover:text-white transition-colors">
        Methodology
      </a>
      <a href="/pricing" class="block text-zinc-400 hover:text-white transition-colors">
        Pricing
      </a>
      <a href="#devtools" class="block text-zinc-400 hover:text-white transition-colors">
        CLI
      </a>
      <a
        href="/signup"
        class="block w-full text-center px-4 py-2 bg-emerald-500 hover:bg-emerald-600
               text-white font-medium rounded-lg transition"
      >
        Get API Key
      </a>
    </div>
  </div>
</nav>

<script>
  const menuBtn = document.getElementById('mobile-menu-btn');
  const mobileMenu = document.getElementById('mobile-menu');
  const menuIcon = document.getElementById('menu-icon');
  const closeIcon = document.getElementById('close-icon');

  menuBtn?.addEventListener('click', () => {
    mobileMenu?.classList.toggle('hidden');
    menuIcon?.classList.toggle('hidden');
    closeIcon?.classList.toggle('hidden');
  });
</script>
```

### 5. Expand Footer (MEDIUM PRIORITY)

**Location:** `src/components/Footer.astro`

```astro
---
const currentYear = new Date().getFullYear();
---

<footer class="border-t border-zinc-800/50 bg-[#09090b]">
  <div class="max-w-5xl mx-auto px-4 py-12">
    <div class="grid grid-cols-2 md:grid-cols-4 gap-8 mb-8">
      <!-- Product -->
      <div>
        <h3 class="text-sm font-semibold text-white mb-4">Product</h3>
        <ul class="space-y-2">
          <li>
            <a href="/docs" class="text-sm text-zinc-400 hover:text-white transition">
              API Documentation
            </a>
          </li>
          <li>
            <a href="/methodology" class="text-sm text-zinc-400 hover:text-white transition">
              Scoring Methodology
            </a>
          </li>
          <li>
            <a href="/pricing" class="text-sm text-zinc-400 hover:text-white transition">
              Pricing
            </a>
          </li>
          <li>
            <a href="/changelog" class="text-sm text-zinc-400 hover:text-white transition">
              Changelog
            </a>
          </li>
        </ul>
      </div>

      <!-- Developers -->
      <div>
        <h3 class="text-sm font-semibold text-white mb-4">Developers</h3>
        <ul class="space-y-2">
          <li>
            <a href="/docs#cli" class="text-sm text-zinc-400 hover:text-white transition">
              CLI Tool
            </a>
          </li>
          <li>
            <a href="/docs#github-action" class="text-sm text-zinc-400 hover:text-white transition">
              GitHub Action
            </a>
          </li>
          <li>
            <a
              href="https://github.com/dephealth"
              target="_blank"
              rel="noopener"
              class="text-sm text-zinc-400 hover:text-white transition"
            >
              GitHub
            </a>
          </li>
        </ul>
      </div>

      <!-- Company -->
      <div>
        <h3 class="text-sm font-semibold text-white mb-4">Company</h3>
        <ul class="space-y-2">
          <li>
            <a href="/about" class="text-sm text-zinc-400 hover:text-white transition">
              About
            </a>
          </li>
          <li>
            <a href="mailto:hello@laranjo.dev" class="text-sm text-zinc-400 hover:text-white transition">
              Contact
            </a>
          </li>
          <li>
            <a
              href="https://twitter.com/dephealth"
              target="_blank"
              rel="noopener"
              class="text-sm text-zinc-400 hover:text-white transition"
            >
              Twitter
            </a>
          </li>
        </ul>
      </div>

      <!-- Legal -->
      <div>
        <h3 class="text-sm font-semibold text-white mb-4">Legal</h3>
        <ul class="space-y-2">
          <li>
            <a href="/privacy" class="text-sm text-zinc-400 hover:text-white transition">
              Privacy Policy
            </a>
          </li>
          <li>
            <a href="/terms" class="text-sm text-zinc-400 hover:text-white transition">
              Terms of Service
            </a>
          </li>
        </ul>
      </div>
    </div>

    <!-- Bottom -->
    <div class="pt-8 border-t border-zinc-800/50 flex flex-col md:flex-row justify-between items-center gap-4">
      <p class="text-sm text-zinc-500">
        © {currentYear} DepHealth. Built by{' '}
        <a href="https://laranjo.dev" class="hover:text-white transition">Laranjo</a>
      </p>
      <div class="flex items-center gap-4">
        <a
          href="https://github.com/dephealth"
          target="_blank"
          rel="noopener"
          class="text-zinc-400 hover:text-white transition"
          aria-label="GitHub"
        >
          <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
          </svg>
        </a>
        <a
          href="https://twitter.com/dephealth"
          target="_blank"
          rel="noopener"
          class="text-zinc-400 hover:text-white transition"
          aria-label="Twitter"
        >
          <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
            <path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z" />
          </svg>
        </a>
      </div>
    </div>
  </div>
</footer>
```

### 6. Create Pricing Page (MEDIUM PRIORITY)

**Create:** `src/pages/pricing.astro`

```astro
---
import Layout from '../layouts/Layout.astro';
import Navbar from '../components/Navbar.astro';
import Footer from '../components/Footer.astro';

const tiers = [
  {
    name: 'Free',
    price: '$0',
    period: 'forever',
    description: 'Perfect for trying out DepHealth',
    features: [
      '5,000 requests/month',
      'Health scores & risk levels',
      'CLI & GitHub Action',
      'Community support',
    ],
    cta: 'Get Started',
    ctaLink: '/signup',
    highlighted: false,
  },
  {
    name: 'Pro',
    price: '$29',
    period: '/month',
    description: 'For teams with growing needs',
    features: [
      '100,000 requests/month',
      'Everything in Free',
      'Priority API access',
      'Email support',
      'Usage analytics',
    ],
    cta: 'Coming Soon',
    ctaLink: '#',
    highlighted: true,
  },
  {
    name: 'Business',
    price: '$99',
    period: '/month',
    description: 'For organizations at scale',
    features: [
      '500,000 requests/month',
      'Everything in Pro',
      'SLA guarantee',
      'Dedicated support',
      'Custom integrations',
    ],
    cta: 'Coming Soon',
    ctaLink: '#',
    highlighted: false,
  },
];
---

<Layout title="Pricing | DepHealth">
  <Navbar />

  <main class="max-w-5xl mx-auto px-4 py-24">
    <div class="text-center mb-16">
      <h1 class="text-4xl font-bold text-white mb-4">
        Simple, transparent pricing
      </h1>
      <p class="text-xl text-zinc-400">
        Start free, upgrade as you grow
      </p>
    </div>

    <div class="grid md:grid-cols-3 gap-8">
      {tiers.map((tier) => (
        <div
          class={`rounded-2xl p-8 ${
            tier.highlighted
              ? 'bg-gradient-to-b from-emerald-500/20 to-transparent border-2 border-emerald-500/50'
              : 'bg-zinc-900/50 border border-zinc-800'
          }`}
        >
          <h3 class="text-xl font-semibold text-white mb-2">{tier.name}</h3>
          <div class="mb-4">
            <span class="text-4xl font-bold text-white">{tier.price}</span>
            <span class="text-zinc-400">{tier.period}</span>
          </div>
          <p class="text-zinc-400 mb-6">{tier.description}</p>

          <ul class="space-y-3 mb-8">
            {tier.features.map((feature) => (
              <li class="flex items-center gap-2 text-zinc-300">
                <svg class="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                </svg>
                {feature}
              </li>
            ))}
          </ul>

          <a
            href={tier.ctaLink}
            class={`block w-full text-center px-6 py-3 rounded-lg font-semibold transition ${
              tier.highlighted
                ? 'btn-gradient text-white'
                : 'bg-zinc-800 text-white hover:bg-zinc-700'
            } ${tier.cta === 'Coming Soon' ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            {tier.cta}
          </a>
        </div>
      ))}
    </div>

    <!-- FAQ -->
    <div class="mt-24">
      <h2 class="text-2xl font-bold text-white text-center mb-12">
        Frequently Asked Questions
      </h2>
      <div class="grid md:grid-cols-2 gap-8">
        <div>
          <h3 class="text-lg font-semibold text-white mb-2">
            What counts as a request?
          </h3>
          <p class="text-zinc-400">
            Each API call counts as one request. A scan of 100 dependencies
            counts as one request, not 100.
          </p>
        </div>
        <div>
          <h3 class="text-lg font-semibold text-white mb-2">
            Can I upgrade or downgrade anytime?
          </h3>
          <p class="text-zinc-400">
            Yes, you can change your plan at any time. Upgrades take effect
            immediately, downgrades at the end of your billing period.
          </p>
        </div>
        <div>
          <h3 class="text-lg font-semibold text-white mb-2">
            What happens if I exceed my limit?
          </h3>
          <p class="text-zinc-400">
            Requests beyond your limit will be rejected with a 429 status code.
            You can upgrade anytime to increase your limit.
          </p>
        </div>
        <div>
          <h3 class="text-lg font-semibold text-white mb-2">
            Do you offer enterprise plans?
          </h3>
          <p class="text-zinc-400">
            Yes! Contact us at hello@laranjo.dev for custom enterprise pricing
            with higher limits and dedicated support.
          </p>
        </div>
      </div>
    </div>
  </main>

  <Footer />
</Layout>
```

### 7. Add Accessibility Improvements (LOW PRIORITY)

**Location:** `src/components/LiveDemo.astro`

**Add form labels and ARIA attributes:**
```astro
<label for="package-input" class="sr-only">Package name</label>
<input
  type="text"
  id="package-input"
  aria-label="Enter npm package name"
  aria-describedby="package-hint"
  placeholder="Enter package name (e.g., express)"
  class="..."
/>
<p id="package-hint" class="sr-only">
  Enter an npm package name to check its health score
</p>

<button
  id="check-btn"
  aria-busy="false"
  class="..."
>
  Check Health
</button>
```

**Add skip link in Layout.astro:**
```astro
<body>
  <a
    href="#main-content"
    class="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4
           focus:z-50 focus:px-4 focus:py-2 focus:bg-emerald-500 focus:text-white
           focus:rounded"
  >
    Skip to main content
  </a>

  <slot />
</body>
```

**Add reduced motion support in global.css:**
```css
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
```

## Files to Create

| File | Purpose |
|------|---------|
| `src/pages/signup.astro` | Self-service signup page |
| `src/pages/pricing.astro` | Pricing page |
| `src/pages/login.astro` | Login page |
| `src/pages/privacy.astro` | Privacy policy |
| `src/pages/terms.astro` | Terms of service |
| `public/robots.txt` | Search engine crawling rules |
| `public/sitemap.xml` | Site structure for SEO |
| `public/og-image.png` | Social sharing image |

## Files to Modify

| File | Changes |
|------|---------|
| `src/layouts/Layout.astro` | Add SEO meta tags, analytics |
| `src/components/Navbar.astro` | Add mobile hamburger menu |
| `src/components/Footer.astro` | Expand with links and social |
| `src/components/CTA.astro` | Update to link to /signup |
| `src/components/LiveDemo.astro` | Add accessibility attributes |
| `src/styles/global.css` | Add reduced motion support |

## Success Criteria

1. Self-service signup page working
2. Analytics tracking page views and events
3. SEO meta tags on all pages
4. Mobile navigation working
5. Footer expanded with all sections
6. Pricing page created
7. Accessibility improvements implemented
8. robots.txt and sitemap.xml created

## Deployment

```bash
cd /home/iebt/projects/startup-experiment/work/dephealth/landing-page

# Build
npm run build

# Deploy to S3/CloudFront
./deploy.sh
```

## Reference

See `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` Section 11 for full landing page analysis.
