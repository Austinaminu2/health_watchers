import { cookies } from "next/headers";
import { useTranslations } from "next-intl";
import { defaultLocale, type Locale } from "../../i18n";
import NavbarClient from "./NavbarClient";
import { useTranslations } from "next-intl";
import { cookies } from "next/headers";
import { defaultLocale, type Locale } from "../../i18n";
import LanguageSwitcher from "./LanguageSwitcher";

export default function Navbar() {
  const t = useTranslations("nav");
  const cookieStore = cookies();
  const locale = (cookieStore.get("locale")?.value as Locale) ?? defaultLocale;

  const links = [
    { href: "/patients", label: t("patients") },
    { href: "/encounters", label: t("encounters") },
    { href: "/payments", label: t("payments") },
  ];

  return <NavbarClient links={links} locale={locale} />;
  return (
    <>
      <a
        href="#main-content"
        style={{
          position: "absolute",
          left: "-9999px",
          top: "auto",
          width: "1px",
          height: "1px",
          overflow: "hidden",
        }}
        onFocus={(e) => {
          e.currentTarget.style.left = "0";
          e.currentTarget.style.width = "auto";
          e.currentTarget.style.height = "auto";
        }}
        onBlur={(e) => {
          e.currentTarget.style.left = "-9999px";
          e.currentTarget.style.width = "1px";
          e.currentTarget.style.height = "1px";
        }}
      >
        Skip to main content
      </a>
      <nav
        aria-label="Main navigation"
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0.75rem 2rem",
          borderBottom: "1px solid #ddd",
          fontFamily: "sans-serif",
        }}
      >
        <ul
          role="list"
          style={{ display: "flex", gap: "1.5rem", margin: 0, padding: 0, listStyle: "none" }}
        >
          <li><a href="/patients">{t("patients")}</a></li>
          <li><a href="/encounters">{t("encounters")}</a></li>
          <li><a href="/payments">{t("payments")}</a></li>
        </ul>
        <LanguageSwitcher current={locale} />
      </nav>
    </>
    <nav
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0.75rem 2rem",
        borderBottom: "1px solid #ddd",
        fontFamily: "sans-serif",
      }}
    >
      <div style={{ display: "flex", gap: "1.5rem" }}>
        <a href="/patients">{t("patients")}</a>
        <a href="/encounters">{t("encounters")}</a>
        <a href="/payments">{t("payments")}</a>
      </div>
      <LanguageSwitcher current={locale} />
    </nav>
  );
}
