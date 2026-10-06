// @ts-check

const path = require('path');
const lightCodeTheme = require('prism-react-renderer').themes.github;
const darkCodeTheme = require('prism-react-renderer').themes.vsDark;

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Shellui storage-service',
  tagline: 'Supabase-compatible storage backend for Shellui',
  favicon: 'img/favicon.ico',
  headTags: [
    {
      tagName: 'link',
      attributes: {
        rel: 'icon',
        type: 'image/png',
        sizes: '32x32',
        href: '/img/favicon-32x32.png',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'icon',
        type: 'image/png',
        sizes: '16x16',
        href: '/img/favicon-16x16.png',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'apple-touch-icon',
        sizes: '180x180',
        href: '/img/apple-touch-icon.png',
      },
    },
  ],

  url: 'https://storage.docs.shellui.com',
  baseUrl: '/',

  organizationName: 'shellui',
  projectName: 'storage-service',

  onBrokenLinks: 'throw',
  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  clientModules: [require.resolve('./src/shellui-init.js')],

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          path: '../../docs',
          routeBasePath: '/',
          sidebarPath: require.resolve('./sidebars.js'),
          editUrl:
            'https://github.com/shellui/storage-service/tree/main/',
          // Same rewrite the central docs site applies: links that leave docs/
          // point at GitHub, and the old docs host stays on this site.
          beforeDefaultRemarkPlugins: [
            [
              require('./plugins/remark-service-links'),
              {
                docsPath: path.resolve(__dirname, '../../docs'),
                repo: 'shellui/storage-service',
                ref: 'develop',
                hostRoutes: {
                  'storage.docs.shellui.com': '/',
                },
              },
            ],
          ],
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      colorMode: {
        defaultMode: 'light',
        disableSwitch: false,
        respectPrefersColorScheme: true,
      },
      navbar: {
        title: '',
        hideOnScroll: false,
        logo: {
          alt: 'Shellui storage-service documentation',
          src: 'img/shellui_documentation_logo.png',
          href: '/',
          height: 28,
          width: 257,
        },
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'tutorialSidebar',
            position: 'left',
            label: 'Documentation',
            className: 'navbar__docs-link',
          },
          {
            href: 'https://docs.shellui.com',
            label: 'Shellui docs',
            position: 'left',
            className: 'navbar__mobile-only-link',
          },
          {
            href: 'https://shellui.com',
            label: 'Shellui.com',
            position: 'left',
            className: 'navbar__mobile-only-link',
          },
          {
            href: 'https://github.com/shellui/storage-service',
            label: 'GitHub',
            position: 'left',
            className: 'navbar__mobile-only-link',
          },
        ],
      },
      footer: {
        style: 'light',
        copyright: `© ${new Date().getFullYear()} Shellui. All rights reserved.`,
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
      },
    }),
};

module.exports = config;
