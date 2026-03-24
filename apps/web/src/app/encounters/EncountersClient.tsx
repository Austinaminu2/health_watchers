"use client";

import { useState, useEffect } from "react";

interface Encounter {
  id: string;
  patientId: string;
  date: string;
  notes: string;
}

interface Labels {
  title: string;
  loading: string;
  empty: string;
  id: string;
  patient: string;
  date: string;
  notes: string;
}

export default function EncountersClient({ labels }: { labels: Labels }) {
  const [encounters, setEncounters] = useState<Encounter[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("http://localhost:3001/api/v1/encounters")
      .then((res) => res.json())
      .then((data) => { setEncounters(data || []); setLoading(false); })
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
      {encounters.length === 0 ? (
        <p role="status">{labels.empty}</p>
      ) : (
        <ul aria-label={labels.title}>
          {encounters.map((e) => (
            <li key={e.id} style={{ margin: "10px 0", padding: "10px", border: "1px solid #ddd" }}>
              <span><strong>{labels.id}:</strong> {e.id}</span>{" | "}
              <span><strong>{labels.patient}:</strong> {e.patientId}</span>{" | "}
              <span><strong>{labels.date}:</strong> {e.date}</span>{" | "}
              <span>{labels.notes}: {e.notes}</span>
        <p>{labels.empty}</p>
      ) : (
        <ul>
          {encounters.map((e) => (
            <li key={e.id} style={{ margin: "10px 0", padding: "10px", border: "1px solid #ddd" }}>
              <strong>{labels.id}:</strong> {e.id} | <strong>{labels.patient}:</strong> {e.patientId} |{" "}
              <strong>{labels.date}:</strong> {e.date} | {labels.notes}: {e.notes}
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}
