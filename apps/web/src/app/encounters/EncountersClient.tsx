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
      <p role="status" aria-live="polite" className="px-4 py-8 text-gray-500">
      <p role="status" aria-live="polite" style={{ padding: "2rem" }}>
        {labels.loading}
      </p>
    );
  }

  return (
    <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      <h1 className="text-2xl sm:text-3xl font-bold text-gray-900 mb-6">{labels.title}</h1>
      {encounters.length === 0 ? (
        <p role="status" className="text-gray-500">{labels.empty}</p>
      ) : (
        <ul aria-label={labels.title} className="flex flex-col gap-4 list-none p-0 m-0">
          {encounters.map((e) => (
            <li key={e.id} className="rounded border border-gray-200 p-4 shadow-sm">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-sm">
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wide">{labels.id}</p>
                  <p className="font-medium text-gray-900 break-all">{e.id}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wide">{labels.patient}</p>
                  <p className="font-medium text-gray-900 break-all">{e.patientId}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wide">{labels.date}</p>
                  <p className="text-gray-700">{e.date}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wide">{labels.notes}</p>
                  <p className="text-gray-700">{e.notes}</p>
                </div>
              </div>
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
