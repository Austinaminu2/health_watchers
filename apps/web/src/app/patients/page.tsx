import { useTranslations } from "next-intl";
import PatientsClient from "./PatientsClient";

export default function PatientsPage() {
  const t = useTranslations("patients");
  return (
    <PatientsClient
      labels={{
        title: t("title"),
        loading: t("loading"),
        empty: t("empty"),
        id: t("id"),
        name: t("name"),
        dob: t("dob"),
      }}
    />
'use client'

import { useState, useEffect, useCallback } from 'react'
import { PageWrapper, PageHeader, Button, SlideOver } from '@/components/ui'
import { PatientTable, type Patient } from '@/components/patients/PatientTable'
import { PatientDetailTabs } from '@/components/patients/PatientDetailTabs'
import { PatientForm, type PatientFormData } from '@/components/forms/PatientForm'

const API_BASE_URL = 'http://localhost:3001/api/v1'

export default function PatientsPage() {
  const [patients, setPatients] = useState<Patient[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [showDetail, setShowDetail] = useState(false)
  const [selectedPatient, setSelectedPatient] = useState<Patient | null>(null)
  const [formMode, setFormMode] = useState<'create' | 'edit'>('create')
  const [submitting, setSubmitting] = useState(false)

  // Fetch all patients
  const fetchPatients = useCallback(async () => {
    try {
      setLoading(true)
      const response = await fetch(`${API_BASE_URL}/patients`)
      if (!response.ok) throw new Error('Failed to fetch patients')
      const data = await response.json()
      setPatients(data.data || [])
    } catch (error) {
      console.error('Error fetching patients:', error)
      setPatients([])
    } finally {
      setLoading(false)
    }
  }, [])

  // Fetch patient details
  const fetchPatientDetails = useCallback(async (id: string) => {
    try {
      const response = await fetch(`${API_BASE_URL}/patients/${id}`)
      if (!response.ok) throw new Error('Failed to fetch patient details')
      const data = await response.json()
      return data.data
    } catch (error) {
      console.error('Error fetching patient details:', error)
      return null
    }
  }, [])

  // Search patients
  const handleSearch = useCallback(async (query: string) => {
    if (!query.trim()) {
      await fetchPatients()
      return
    }

    try {
      setLoading(true)
      const response = await fetch(`${API_BASE_URL}/patients/search?q=${encodeURIComponent(query)}`)
      if (!response.ok) throw new Error('Search failed')
      const data = await response.json()
      setPatients(data.data || [])
    } catch (error) {
      console.error('Search error:', error)
    } finally {
      setLoading(false)
    }
  }, [fetchPatients])

  // Load initial patients on mount
  useEffect(() => {
    fetchPatients()
  }, [fetchPatients])

  // Handle edit button
  const handleEdit = useCallback((patient: Patient) => {
    setSelectedPatient(patient)
    setFormMode('edit')
    setShowForm(true)
    setShowDetail(false)
  }, [])

  // Handle view details button
  const handleViewDetails = useCallback(async (patient: Patient) => {
    const details = await fetchPatientDetails(patient._id)
    if (details) {
      setSelectedPatient(details)
      setShowDetail(true)
      setShowForm(false)
    }
  }, [fetchPatientDetails])

  // Handle new patient button
  const handleNewPatient = useCallback(() => {
    setSelectedPatient(null)
    setFormMode('create')
    setShowForm(true)
    setShowDetail(false)
  }, [])

  // Handle form submit
  const handleFormSubmit = useCallback(async (formData: PatientFormData) => {
    setSubmitting(true)
    try {
      const url = formMode === 'create'
        ? `${API_BASE_URL}/patients`
        : `${API_BASE_URL}/patients/${selectedPatient?._id}`
      
      const method = formMode === 'create' ? 'POST' : 'PUT'
      
      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      })

      if (!response.ok) throw new Error('Failed to save patient')
      
      // Refresh patient list
      await fetchPatients()
      setShowForm(false)
      setSelectedPatient(null)
    } catch (error) {
      console.error('Error saving patient:', error)
      alert('Failed to save patient. Please try again.')
    } finally {
      setSubmitting(false)
    }
  }, [formMode, selectedPatient, fetchPatients])

  // Handle form cancel
  const handleFormCancel = useCallback(() => {
    setShowForm(false)
    setShowDetail(false)
    setSelectedPatient(null)
  }, [])

  return (
    <PageWrapper className="py-8">
      {showDetail && selectedPatient ? (
        // Detail View
        <div className="space-y-6">
          <button
            onClick={() => setShowDetail(false)}
            className="text-sm text-primary-600 hover:text-primary-700"
          >
            ← Back to Patients
          </button>
          <PatientDetailTabs
            patientName={`${selectedPatient.firstName} ${selectedPatient.lastName}`}
            patientId={selectedPatient._id}
            patientInfo={{
              dateOfBirth: selectedPatient.dateOfBirth,
              gender: selectedPatient.gender,
              phone: selectedPatient.phone,
              address: selectedPatient.address,
            }}
            tabs={[
              {
                id: 'overview',
                label: 'Overview',
                content: (
                  <div className="space-y-4">
                    <div>
                      <h3 className="text-sm font-semibold text-secondary-900">Medical History</h3>
                      <p className="text-sm text-secondary-600">No medical history records available.</p>
                    </div>
                  </div>
                ),
              },
              {
                id: 'encounters',
                label: 'Encounters',
                content: (
                  <div className="space-y-4">
                    <p className="text-sm text-secondary-600">No encounters available for this patient.</p>
                  </div>
                ),
              },
              {
                id: 'payments',
                label: 'Payments',
                content: (
                  <div className="space-y-4">
                    <p className="text-sm text-secondary-600">No payment records available.</p>
                  </div>
                ),
              },
              {
                id: 'documents',
                label: 'Documents',
                content: (
                  <div className="space-y-4">
                    <p className="text-sm text-secondary-600">No documents available.</p>
                  </div>
                ),
              },
            ]}
          />
          <Button
            variant="secondary"
            onClick={() => {
              handleEdit(selectedPatient)
            }}
          >
            Edit Patient
          </Button>
        </div>
      ) : (
        // List View
        <>
          <PageHeader
            title="Patients"
            subtitle="Manage and view patient information"
            actions={
              <Button
                variant="primary"
                onClick={handleNewPatient}
              >
                + New Patient
              </Button>
            }
          />

          <PatientTable
            patients={patients}
            isLoading={loading}
            onEdit={handleEdit}
            onViewDetails={handleViewDetails}
            onSearch={handleSearch}
          />
        </>
      )}

      {/* Patient Form Slide Over */}
      <SlideOver
        isOpen={showForm}
        onClose={handleFormCancel}
        title={formMode === 'create' ? 'New Patient' : 'Edit Patient'}
        subtitle={formMode === 'create' ? 'Add a new patient to the system' : 'Update patient information'}
        width="w-full sm:w-[400px]"
      >
        <PatientForm
          initialData={formMode === 'edit' && selectedPatient
            ? {
              firstName: selectedPatient.firstName,
              lastName: selectedPatient.lastName,
              dateOfBirth: selectedPatient.dateOfBirth?.split('T')[0] || '',
              sex: (selectedPatient.gender === 'male' ? 'M' : selectedPatient.gender === 'female' ? 'F' : 'O') as 'M' | 'F' | 'O',
              contactNumber: selectedPatient.phone || '',
              address: selectedPatient.address || '',
            }
            : undefined}
          isLoading={submitting}
          onSubmit={handleFormSubmit}
          onCancel={handleFormCancel}
        />
      </SlideOver>
    </PageWrapper>
  )
}
          </TableHeader>
          <TableBody>
            {patients.map(patient => (
              <TableRow key={patient.id}>
                <TableCell className="font-mono text-sm">{patient.id}</TableCell>
                <TableCell className="font-medium">{patient.name}</TableCell>
                <TableCell>{patient.dob}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        
        {patients.length === 0 && (
          <div className="text-center py-8">
            <p className="text-secondary-600">No patients found. API stub - implement CRUD.</p>
          </div>
        )}
      </div>
    </PageWrapper>
  );
}
