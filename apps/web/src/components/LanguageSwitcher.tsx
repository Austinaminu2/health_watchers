"use client";

import { useTransition } from "react";
import { useRouter } from "next/navigation";
import { locales, type Locale } from "../../i18n";

const labels: Record<Locale, string> = {
  en: "English",
  fr: "Français",
};

export default function LanguageSwitcher({ current }: { current: Locale }) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();

  function switchLocale(locale: Locale) {
    document.cookie = `locale=${locale};path=/;max-age=${60 * 60 * 24 * 365}`;
    startTransition(() => router.refresh());
  }

  return (
    <div
      role="group"
      aria-label="Language selection"
      style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}
    >
      {locales.map((locale) => {
        const isCurrent = locale === current;
        return (
          <button
            key={locale}
            onClick={() => switchLocale(locale)}
            disabled={isCurrent || isPending}
            aria-pressed={isCurrent}
            aria-label={`Switch language to ${labels[locale]}`}
            style={{
              padding: "4px 10px",
              cursor: isCurrent ? "default" : "pointer",
              fontWeight: isCurrent ? "bold" : "normal",
              border: "1px solid #ccc",
              borderRadius: "4px",
              background: isCurrent ? "#e0e0e0" : "white",
            }}
          >
            {labels[locale]}
          </button>
        );
      })}
    <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
      {locales.map((locale) => (
        <button
          key={locale}
          onClick={() => switchLocale(locale)}
          disabled={locale === current || isPending}
          style={{
            padding: "4px 10px",
            cursor: locale === current ? "default" : "pointer",
            fontWeight: locale === current ? "bold" : "normal",
            border: "1px solid #ccc",
            borderRadius: "4px",
            background: locale === current ? "#e0e0e0" : "white",
          }}
          aria-current={locale === current ? "true" : undefined}
        >
          {labels[locale]}
        </button>
      ))}
    </div>
  );
}
