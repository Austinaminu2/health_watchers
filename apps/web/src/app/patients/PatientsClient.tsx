"use client";

import { useState, useEffect } from "react";

interface Patient {
  id: string;
  name: string;
  dob: string;
}

interface Labels {
  title: string;
  loading: string;
  empty: string;
  id: string;
  name: string;
  dob: string;
}

export default function PatientsClient({ labels }: { labels: Labels }) {
  const [patients, setPatients] = useState<Patient[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("http://localhost:3001/api/v1/patients")
      .then((res) => res.json())
      .then((data) => { setPatients(data || []); setLoading(false); })
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
      {patients.length === 0 ? (
        <p role="status" className="text-gray-500">{labels.empty}</p>
      ) : (
        <>
          {/* Card layout on mobile, table on md+ */}
          <div className="md:hidden flex flex-col gap-4">
            {patients.map((p) => (
              <div key={p.id} className="rounded border border-gray-200 p-4 shadow-sm">
                <p className="text-xs text-gray-500 uppercase tracking-wide">{labels.id}</p>
                <p className="font-medium text-gray-900">{p.id}</p>
                <p className="mt-2 text-xs text-gray-500 uppercase tracking-wide">{labels.name}</p>
                <p className="font-medium text-gray-900">{p.name}</p>
                <p className="mt-2 text-xs text-gray-500 uppercase tracking-wide">{labels.dob}</p>
                <p className="text-gray-700">{p.dob}</p>
              </div>
            ))}
          </div>

          <div className="hidden md:block overflow-x-auto">
            <table aria-label={labels.title} className="w-full border-collapse text-sm">
              <thead>
                <tr className="bg-gray-50">
                  <th scope="col" className="border border-gray-200 px-4 py-2 text-left">{labels.id}</th>
                  <th scope="col" className="border border-gray-200 px-4 py-2 text-left">{labels.name}</th>
                  <th scope="col" className="border border-gray-200 px-4 py-2 text-left">{labels.dob}</th>
                </tr>
              </thead>
              <tbody>
                {patients.map((p) => (
                  <tr key={p.id} className="even:bg-gray-50">
                    <td className="border border-gray-200 px-4 py-2">{p.id}</td>
                    <td className="border border-gray-200 px-4 py-2">{p.name}</td>
                    <td className="border border-gray-200 px-4 py-2">{p.dob}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
  if (loading) return <p style={{ padding: "2rem" }}>{labels.loading}</p>;

  return (
    <main style={{ padding: "2rem", fontFamily: "sans-serif" }}>
      <h1>{labels.title}</h1>
      {patients.length === 0 ? (
        <p role="status">{labels.empty}</p>
      ) : (
        <table
          aria-label={labels.title}
          style={{ width: "100%", borderCollapse: "collapse" }}
        >
          <thead>
            <tr>
              <th scope="col" style={{ border: "1px solid #ddd", padding: "8px" }}>{labels.id}</th>
              <th scope="col" style={{ border: "1px solid #ddd", padding: "8px" }}>{labels.name}</th>
              <th scope="col" style={{ border: "1px solid #ddd", padding: "8px" }}>{labels.dob}</th>
        <p>{labels.empty}</p>
      ) : (
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              {[labels.id, labels.name, labels.dob].map((h) => (
                <th key={h} style={{ border: "1px solid #ddd", padding: "8px" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {patients.map((p) => (
              <tr key={p.id}>
                <td style={{ border: "1px solid #ddd", padding: "8px" }}>{p.id}</td>
                <td style={{ border: "1px solid #ddd", padding: "8px" }}>{p.name}</td>
                <td style={{ border: "1px solid #ddd", padding: "8px" }}>{p.dob}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
