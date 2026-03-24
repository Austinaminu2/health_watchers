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
      <p role="status" aria-live="polite" style={{ padding: "2rem" }}>
        {labels.loading}
      </p>
    );
  }
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
