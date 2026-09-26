import React, {useEffect, useRef, useState} from 'react';
import {flushSync} from 'react-dom';
import {useColorMode} from '@docusaurus/theme-common';
import useBaseUrl from '@docusaurus/useBaseUrl';
import IconMenu from '@theme/Icon/Menu';
import {
  isShelluiEmbedded,
  sendColorSchemeToShell,
} from '../../../lib/shelluiTheme';

const THEME_OPTIONS = [
  {value: 'light', label: 'Light'},
  {value: 'dark', label: 'Dark'},
  {value: 'system', label: 'System'},
];

function GitHubIcon() {
  return (
    <svg fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
      />
    </svg>
  );
}

function DocsIcon() {
  return (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
    </svg>
  );
}

function applyColorModeWithTransition(setColorMode, nextMode, event) {
  const prefersReducedMotion = window.matchMedia(
    '(prefers-reduced-motion: reduce)',
  ).matches;

  if (
    isShelluiEmbedded() ||
    !document.startViewTransition ||
    prefersReducedMotion
  ) {
    setColorMode(nextMode, {persist: !isShelluiEmbedded()});
    return;
  }

  if (event) {
    document.documentElement.style.setProperty('--x', `${event.clientX}px`);
    document.documentElement.style.setProperty('--y', `${event.clientY}px`);
  }

  document.startViewTransition(() => {
    flushSync(() => {
      setColorMode(nextMode);
    });
  });
}

export default function DesktopMenu() {
  const [open, setOpen] = useState(false);
  const rootRef = useRef(null);
  const {colorMode, colorModeChoice, setColorMode} = useColorMode();
  const selected = colorModeChoice === null ? 'system' : colorModeChoice;
  const shelluiIcon = useBaseUrl('/img/shellui-icon.png');

  useEffect(() => {
    if (!open) {
      return undefined;
    }

    const onPointerDown = (event) => {
      if (!rootRef.current?.contains(event.target)) {
        setOpen(false);
      }
    };
    const onKeyDown = (event) => {
      if (event.key === 'Escape') {
        setOpen(false);
      }
    };

    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  const onThemeOptionClick = (event, optionValue) => {
    if (selected === optionValue) {
      return;
    }

    const nextMode = optionValue === 'system' ? null : optionValue;
    const nextEffective =
      nextMode === null
        ? window.matchMedia('(prefers-color-scheme: dark)').matches
          ? 'dark'
          : 'light'
        : nextMode;

    if (nextEffective === colorMode) {
      setColorMode(nextMode, {persist: !isShelluiEmbedded()});
      if (isShelluiEmbedded()) {
        sendColorSchemeToShell(optionValue);
      }
      return;
    }

    applyColorModeWithTransition(setColorMode, nextMode, event);
    if (isShelluiEmbedded()) {
      sendColorSchemeToShell(optionValue);
    }
  };

  return (
    <div className="navbar-desktop-menu" ref={rootRef}>
      <button
        type="button"
        className="clean-btn navbar-desktop-menu__toggle"
        aria-label="Open menu"
        aria-expanded={open}
        aria-haspopup="true"
        onClick={() => setOpen((value) => !value)}>
        <IconMenu />
      </button>
      {open && (
        <div className="navbar-desktop-menu__dropdown" role="menu">
          <a
            className="navbar-desktop-menu__link"
            href="https://shellui.com"
            role="menuitem"
            onClick={() => setOpen(false)}>
            <span className="navbar-desktop-menu__lead">
              <img
                className="navbar-desktop-menu__brand-icon"
                src={shelluiIcon}
                alt=""
                width={16}
                height={16}
              />
            </span>
            <span className="navbar-desktop-menu__label">Shellui.com</span>
            <span className="navbar-desktop-menu__dot navbar-desktop-menu__dot--empty" />
          </a>
          <a
            className="navbar-desktop-menu__link"
            href="https://docs.shellui.com"
            role="menuitem"
            onClick={() => setOpen(false)}>
            <span className="navbar-desktop-menu__lead">
              <DocsIcon />
            </span>
            <span className="navbar-desktop-menu__label">Shellui docs</span>
            <span className="navbar-desktop-menu__dot navbar-desktop-menu__dot--empty" />
          </a>
          <a
            className="navbar-desktop-menu__link"
            href="https://github.com/shellui/storage-service"
            target="_blank"
            rel="noopener noreferrer"
            role="menuitem"
            onClick={() => setOpen(false)}>
            <span className="navbar-desktop-menu__lead">
              <GitHubIcon />
            </span>
            <span className="navbar-desktop-menu__label">GitHub</span>
            <span className="navbar-desktop-menu__dot navbar-desktop-menu__dot--empty" />
          </a>
          <div className="navbar-desktop-menu__separator" />
          {THEME_OPTIONS.map((option) => {
            const isSelected = selected === option.value;
            return (
              <button
                key={option.value}
                type="button"
                className="clean-btn navbar-desktop-menu__link"
                role="menuitemradio"
                aria-checked={isSelected}
                onClick={(event) => onThemeOptionClick(event, option.value)}>
                <span className="navbar-desktop-menu__lead" />
                <span className="navbar-desktop-menu__label">{option.label}</span>
                <span
                  className={
                    isSelected
                      ? 'navbar-desktop-menu__dot'
                      : 'navbar-desktop-menu__dot navbar-desktop-menu__dot--empty'
                  }
                  aria-hidden="true"
                />
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
