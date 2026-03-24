import type { Metadata } from "next";
import { NextIntlClientProvider } from "next-intl";
import { getMessages, getLocale } from "next-intl/server";
import Navbar from "../components/Navbar";
import "./globals.css";

export const metadata: Metadata = {
  title: "Health Watchers",
  description: "AI-assisted EMR powered by Stellar blockchain",
  robots: {
    index: false,
    follow: false,
  },
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const locale = await getLocale();
  const messages = await getMessages();

  return (
    <html lang={locale}>
      <body>
        <NextIntlClientProvider locale={locale} messages={messages}>
          <Navbar />
          {children}
        </NextIntlClientProvider>
    <html lang="en">
      <body className="min-h-screen bg-neutral-50 font-sans antialiased">
        {children}
      </body>
    </html>
  );
}
