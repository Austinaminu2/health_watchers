import { useTranslations } from "next-intl";
import { PageWrapper, PageHeader } from '@/components/ui'

export default function HomePage() {
  const t = useTranslations("home");
  return (
    <main style={{ fontFamily: "sans-serif", padding: "2rem" }}>
      <h1>{t("title")}</h1>
      <p>{t("subtitle")}</p>
    </main>
    <PageWrapper className="py-8">
      <PageHeader 
        title="Health Watchers"
        subtitle="AI-assisted EMR powered by Stellar blockchain"
      />
      <nav className="flex items-center gap-6">
        <a 
          href="/patients" 
          className="text-primary-600 hover:text-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 rounded-md px-2 py-1 transition-colors"
        >
          Patients
        </a>
        <span className="text-secondary-400">|</span>
        <a 
          href="/encounters" 
          className="text-primary-600 hover:text-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 rounded-md px-2 py-1 transition-colors"
        >
          Encounters
        </a>
        <span className="text-secondary-400">|</span>
        <a 
          href="/payments" 
          className="text-primary-600 hover:text-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 rounded-md px-2 py-1 transition-colors"
        >
          Payments
        </a>
      </nav>
    </PageWrapper>
  );
}
