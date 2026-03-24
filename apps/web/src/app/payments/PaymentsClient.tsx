"use client";

import { useState, useEffect } from "react";

interface Payment {
  id: string;
  patientId: string;
  amount: string;
  status: string;
  txHash?: string;
}

interface Labels {
  title: string;
  loading: string;
  empty: string;
  id: string;
  patient: string;
  amount: string;
  status: string;
  view: string;
}

export default function PaymentsClient({ labels }: { labels: Labels }) {
  const [payments, setPayments] = useState<Payment[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("http://localhost:3001/api/v1/payments")
      .then((res) => res.json())
      .then((data) => { setPayments(data || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <p role="status" aria-live="polite" style={{ padding: "2rem" }}>
        {labels.loading}
      </p>
    );
  }
  if (loading) return <p style={{ padding: "2rem" }}>{labels.loading}</p>;

  return (
    <main style={{ padding: "2rem", fontFamily: "sans-serif" }}>
      <h1>{labels.title}</h1>
      {payments.length === 0 ? (
        <p role="status">{labels.empty}</p>
      ) : (
        <ul aria-label={labels.title}>
          {payments.map((p) => (
            <li key={p.id} style={{ margin: "10px 0", padding: "10px", border: "1px solid #ddd" }}>
              <span><strong>{labels.id}:</strong> {p.id}</span>{" | "}
              <span><strong>{labels.patient}:</strong> {p.patientId}</span>{" | "}
              <span>{labels.amount}: {p.amount} XLM</span>{" | "}
              <span>{labels.status}: {p.status}</span>
              {p.txHash && (
                <span>
                  {" | "}
        <p>{labels.empty}</p>
      ) : (
        <ul>
          {payments.map((p) => (
            <li key={p.id} style={{ margin: "10px 0", padding: "10px", border: "1px solid #ddd" }}>
              <strong>{labels.id}:</strong> {p.id} | <strong>{labels.patient}:</strong> {p.patientId} |{" "}
              {labels.amount}: {p.amount} XLM | {labels.status}: {p.status}
              {p.txHash && (
                <span>
                  {" "}
                  |{" "}
                  <a
                    href={`https://stellar.expert/explorer/testnet/tx/${p.txHash}`}
                    target="_blank"
                    rel="noreferrer"
                    aria-label={`${labels.view} transaction ${p.txHash} on Stellar Explorer (opens in new tab)`}
                  >
                    {labels.view}
                  </a>
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}
