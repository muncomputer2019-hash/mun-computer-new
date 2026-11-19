import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Check,
  Edit3,
  FileText,
  Filter,
  Layers,
  Plus,
  Search,
  Settings2,
  Trash2,
  Zap,
} from 'lucide-react';
import {
  DynamicFieldType,
  DynamicFormFieldDef,
  ErpServiceItem,
  ServiceCategoryItem,
  UserProfile,
} from '../../modules/types';
import { erpApi } from '../../services/erpApi';
import { Button } from '../../components/Button';
import { Modal } from '../../components/Modal';
import { formatCurrency } from '../../services/apiClient';
import { extractFriendlyErrorMessage } from '../../services/firebase';

interface ServicesCatalogPageProps {
  currentUser: UserProfile;
  onStartApplicationForService: (serviceId: string) => void;
  onShowToast: (type: 'success' | 'error' | 'info', title: string, description?: string) => void;
}

const ALL_FIELD_TYPES: Array<{ value: DynamicFieldType; label: string }> = [
  { value: 'short_text', label: 'Short Text' },
  { value: 'long_text', label: 'Long Text' },
  { value: 'number', label: 'Number' },
  { value: 'date', label: 'Date' },
  { value: 'mobile', label: 'Mobile Number' },
  { value: 'email', label: 'Email' },
  { value: 'dropdown', label: 'Dropdown' },
  { value: 'radio', label: 'Radio Selection' },
  { value: 'checkbox', label: 'Checkbox' },
  { value: 'multi_select', label: 'Multi-Select' },
  { value: 'file_upload', label: 'File / Document Upload' },
  { value: 'aadhaar', label: 'Aadhaar Number (Masked)' },
  { value: 'pan', label: 'PAN Card Number' },
  { value: 'address', label: 'Postal Address' },
];

export const ServicesCatalogPage: React.FC<ServicesCatalogPageProps> = ({
  currentUser,
  onStartApplicationForService,
  onShowToast,
}) => {
  const isAdmin = currentUser.role === 'ADMIN' || currentUser.role === 'MANAGER';
  const [services, setServices] = useState<ErpServiceItem[]>([]);
  const [categories, setCategories] = useState<ServiceCategoryItem[]>([]);
  const [loading, setLoading] = useState(true);

  // Filtering & Pagination state
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategoryFilter, setSelectedCategoryFilter] = useState<string>('ALL');
  const [rateFilter, setRateFilter] = useState<'ALL' | 'CONFIGURED' | 'BLANK'>('ALL');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 10;

  // Selected Service for Configuration & Builder
  const [selectedService, setSelectedService] = useState<ErpServiceItem | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<'form' | 'docs' | 'sla' | 'automation' | 'pricing'>('form');

  // Modals & Form Submit States
  const [newServiceOpen, setNewServiceOpen] = useState(false);
  const [newCatOpen, setNewCatOpen] = useState(false);
  const [applyModalOpen, setApplyModalOpen] = useState(false);
  const [applyingService, setApplyingService] = useState<ErpServiceItem | null>(null);
  const [savingCat, setSavingCat] = useState(false);
  const [savingSrv, setSavingSrv] = useState(false);
  const [savingPricing, setSavingPricing] = useState(false);
  const [publishingForm, setPublishingForm] = useState(false);
  const [catError, setCatError] = useState<string | null>(null);
  const [srvError, setSrvError] = useState<string | null>(null);
  const [applyError, setApplyError] = useState<string | null>(null);

  // Apply Service form state
  const [applyCustName, setApplyCustName] = useState('');
  const [applyCustMobile, setApplyCustMobile] = useState('');
  const [applyVillage, setApplyVillage] = useState('');
  const [applyFormData, setApplyFormData] = useState<Record<string, string>>({});
  const [submittingApp, setSubmittingApp] = useState(false);

  // Category Form
  const [catForm, setCatForm] = useState({ name: '', description: '' });

  // Service Creation Form
  const [srvForm, setSrvForm] = useState({
    name: '',
    serviceCode: '',
    categoryId: 1,
    customerCharge: 500,
    serviceCost: 150,
    description: '',
    expectedDays: 3,
  });

  // Dynamic Form Builder draft fields
  const [draftFields, setDraftFields] = useState<DynamicFormFieldDef[]>([]);
  const [newField, setNewField] = useState<{
    label: string;
    fieldKey: string;
    fieldType: DynamicFieldType;
    required: boolean;
    optionsCsv: string;
  }>({
    label: '',
    fieldKey: '',
    fieldType: 'short_text',
    required: true,
    optionsCsv: '',
  });

  // Pricing edit buffer
  const [editCharge, setEditCharge] = useState(0);
  const [editCost, setEditCost] = useState(0);
  const [editStatus, setEditStatus] = useState<ErpServiceItem['status']>('Active');

  // Delete Service State & Modal
  const [deleteServiceModalOpen, setDeleteServiceModalOpen] = useState(false);
  const [serviceToDelete, setServiceToDelete] = useState<ErpServiceItem | null>(null);
  const [deletingService, setDeletingService] = useState(false);

  const promptDeleteService = (svc: ErpServiceItem) => {
    setServiceToDelete(svc);
    setDeleteServiceModalOpen(true);
  };

  const handleExecuteDeleteService = async () => {
    if (!serviceToDelete) return;
    setDeletingService(true);
    try {
      await erpApi.deleteService(serviceToDelete.serviceId);
      onShowToast('success', 'Service Deleted', `Service ${serviceToDelete.serviceId} (${serviceToDelete.name}) deleted successfully from database & Firestore.`);
      setDeleteServiceModalOpen(false);
      setServiceToDelete(null);
      await loadAll();
    } catch (err) {
      onShowToast('error', 'Delete Failed', extractFriendlyErrorMessage(err, 'Unable to delete service.'));
    } finally {
      setDeletingService(false);
    }
  };

  const selectedServiceRef = useRef<ErpServiceItem | null>(null);
  useEffect(() => {
    selectedServiceRef.current = selectedService;
  }, [selectedService]);

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [sRes, cRes] = await Promise.all([
        erpApi.listServices(),
        erpApi.listServiceCategories(),
      ]);
      setServices(sRes.data);
      setCategories(cRes.data);
      const currentSelected = selectedServiceRef.current;
      const target = currentSelected
        ? sRes.data.find((s) => s.serviceId === currentSelected.serviceId) ?? sRes.data[0] ?? null
        : sRes.data[0] ?? null;
      if (target) {
        setSelectedService(target);
        setDraftFields(
          target.formVersions.find((v) => v.versionNo === target.currentFormVersion)?.fields ?? []
        );
        setEditCharge(target.customerCharge);
        setEditCost(target.serviceCost);
        setEditStatus(target.status);
      }
    } catch (err) {
      onShowToast('error', 'Failed to load Services', extractFriendlyErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }, [onShowToast]);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  const selectService = (svc: ErpServiceItem) => {
    setSelectedService(svc);
    const activeVer =
      svc.formVersions.find((v) => v.versionNo === svc.currentFormVersion) ??
      svc.formVersions[svc.formVersions.length - 1];
    setDraftFields(activeVer ? [...activeVer.fields] : []);
    setEditCharge(svc.customerCharge);
    setEditCost(svc.serviceCost);
    setEditStatus(svc.status);
  };

  const handleAddField = () => {
    if (!newField.label.trim()) return;
    const key =
      (newField.fieldKey.trim() || newField.label.trim())
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_');
    const options =
      ['dropdown', 'radio', 'multi_select'].includes(newField.fieldType) && newField.optionsCsv
        ? newField.optionsCsv.split(',').map((s) => s.trim()).filter(Boolean)
        : undefined;
    setDraftFields((prev) => [
      ...prev,
      {
        fieldKey: key,
        label: newField.label.trim(),
        fieldType: newField.fieldType,
        required: newField.required,
        displayOrder: prev.length + 1,
        options,
        enabled: true,
      },
    ]);
    setNewField({ label: '', fieldKey: '', fieldType: 'short_text', required: true, optionsCsv: '' });
  };

  const handlePublishFormVersion = async () => {
    if (!selectedService) return;
    setPublishingForm(true);
    try {
      const res = await erpApi.publishFormVersion(selectedService.serviceId, draftFields);
      onShowToast('success', 'Form Version Published', `v${res.data.currentFormVersion} active (historical applications unaffected)`);
      selectService(res.data);
      setServices((prev) => prev.map((s) => (s.serviceId === res.data.serviceId ? res.data : s)));
    } catch (err) {
      onShowToast('error', 'Publish Failed', extractFriendlyErrorMessage(err));
    } finally {
      setPublishingForm(false);
    }
  };

  const handleSavePricingAndStatus = async () => {
    if (!selectedService) return;
    setSavingPricing(true);
    try {
      const res = await erpApi.updateService(selectedService.serviceId, {
        customerCharge: editCharge,
        serviceCost: editCost,
        status: editStatus,
      });
      onShowToast(
        'success',
        'Service Pricing Updated',
        `Profit: ${formatCurrency(res.data.profitAmount)}. Historical applications preserved.`
      );
      selectService(res.data);
      setServices((prev) => prev.map((s) => (s.serviceId === res.data.serviceId ? res.data : s)));
    } catch (err) {
      onShowToast('error', 'Update Failed', extractFriendlyErrorMessage(err));
    } finally {
      setSavingPricing(false);
    }
  };

  const handleCreateService = async (e: React.FormEvent) => {
    e.preventDefault();
    setSrvError(null);
    if (!srvForm.name.trim() || srvForm.name.trim().length < 2) {
      setSrvError('Service name must be at least 2 characters.');
      return;
    }
    setSavingSrv(true);
    try {
      const res = await erpApi.createService({
        name: srvForm.name.trim(),
        serviceCode: srvForm.serviceCode.trim() || undefined,
        categoryId: Number(srvForm.categoryId) || categories[0]?.id || 1,
        customerCharge: Number(srvForm.customerCharge || 0),
        serviceCost: Number(srvForm.serviceCost || 0),
        description: srvForm.description.trim(),
        sla: { processingMode: 'FIXED', expectedDays: Number(srvForm.expectedDays || 3) },
      });
      setNewServiceOpen(false);
      setSrvForm({
        name: '',
        serviceCode: '',
        categoryId: categories[0]?.id ?? 1,
        customerCharge: 500,
        serviceCost: 150,
        description: '',
        expectedDays: 3,
      });
      onShowToast('success', 'Service Created', `${res.data.serviceId} — ${res.data.name}`);
      await loadAll();
    } catch (err) {
      const msg = extractFriendlyErrorMessage(err, 'Unable to create service.');
      setSrvError(msg);
      onShowToast('error', 'Creation Failed', msg);
    } finally {
      setSavingSrv(false);
    }
  };

  const handleCreateCategory = async (e: React.FormEvent) => {
    e.preventDefault();
    setCatError(null);
    if (!catForm.name.trim() || catForm.name.trim().length < 2) {
      setCatError('Category name must be at least 2 characters.');
      return;
    }
    setSavingCat(true);
    try {
      const res = await erpApi.createServiceCategory({
        name: catForm.name.trim(),
        description: catForm.description.trim(),
      });
      setNewCatOpen(false);
      setCatForm({ name: '', description: '' });
      onShowToast('success', 'Category Created', `Created "${res.data.name}" (${res.data.status})`);
      await loadAll();
    } catch (err) {
      const msg = extractFriendlyErrorMessage(err, 'Unable to save category.');
      setCatError(msg);
      onShowToast('error', 'Category Error', msg);
    } finally {
      setSavingCat(false);
    }
  };

  // Filtered Services
  const filteredServices = services.filter((s) => {
    if (selectedCategoryFilter !== 'ALL' && String(s.categoryId) !== String(selectedCategoryFilter)) {
      return false;
    }
    if (rateFilter === 'CONFIGURED' && s.customerCharge <= 0) return false;
    if (rateFilter === 'BLANK' && s.customerCharge > 0) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        s.serviceId.toLowerCase().includes(q) ||
        s.name.toLowerCase().includes(q) ||
        s.categoryName.toLowerCase().includes(q) ||
        s.serviceCode.toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  const totalPages = Math.ceil(filteredServices.length / pageSize) || 1;
  const paginatedServices = filteredServices.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const handleOpenApplyWorkflow = (svc: ErpServiceItem) => {
    setApplyingService(svc);
    setApplyCustName('');
    setApplyCustMobile('');
    setApplyVillage('');
    setApplyFormData({});
    setApplyError(null);
    setApplyModalOpen(true);
  };

  const handleExecuteApplyService = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!applyingService) return;
    setApplyError(null);
    if (!applyCustName.trim() || applyCustMobile.trim().length < 10) {
      const msg = 'Customer Name and valid 10-digit mobile number are required.';
      setApplyError(msg);
      onShowToast('error', 'Validation Failed', msg);
      return;
    }

    setSubmittingApp(true);
    try {
      // First create or get customer
      const custRes = await erpApi.createCustomer({
        fullName: applyCustName.trim(),
        mobile: applyCustMobile.trim(),
        village: applyVillage.trim() || 'Local Area',
        district: 'Murshidabad',
      });
      const customerId = custRes.data.customerId;

      // Create application linked to service and customer
      const appRes = await erpApi.createApplication({
        customerId,
        serviceId: applyingService.serviceId,
        formData: applyFormData,
        adminRemarks: `Applied via centralized Services Catalog workflow for ${applyingService.name}`,
      });

      onShowToast(
        'success',
        'Application Submitted Successfully!',
        `Reference No: ${appRes.data.applicationNo} linked to customer ${customerId}.`
      );
      setApplyModalOpen(false);
      onStartApplicationForService(applyingService.serviceId);
    } catch (err) {
      const msg = extractFriendlyErrorMessage(err, 'Application submission failed.');
      setApplyError(msg);
      onShowToast('error', 'Application Submission Failed', msg);
    } finally {
      setSubmittingApp(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-neutral-950 dark:text-white">
            Services, Form Builder &amp; SLA Configuration
          </h2>
          <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-1">
            Centralized category-wise service catalog, dynamic form builder, version control, required checklists &amp; SLA rules
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {isAdmin && (
            <>
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => {
                  setCatError(null);
                  setCatForm({ name: '', description: '' });
                  setNewCatOpen(true);
                }}
                icon={<Layers className="h-3.5 w-3.5" />}
              >
                Add Category
              </Button>
              <Button
                type="button"
                size="sm"
                variant="primary"
                onClick={() => {
                  setSrvError(null);
                  setSrvForm((prev) => ({
                    ...prev,
                    categoryId: categories[0]?.id ?? prev.categoryId ?? 1,
                  }));
                  setNewServiceOpen(true);
                }}
                icon={<Plus className="h-3.5 w-3.5" />}
              >
                Add Service
              </Button>
            </>
          )}
        </div>
      </div>

      {/* Category Navigation Bar */}
      <div className="bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 rounded-lg p-3">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold text-neutral-700 dark:text-neutral-300">
            Category Navigation ({categories.length} Categories)
          </span>
          <span className="text-xs text-neutral-500">
            Showing {filteredServices.length} Service(s)
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <button
            type="button"
            onClick={() => {
              setSelectedCategoryFilter('ALL');
              setCurrentPage(1);
            }}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors cursor-pointer ${
              selectedCategoryFilter === 'ALL'
                ? 'bg-neutral-950 text-white dark:bg-white dark:text-neutral-950'
                : 'bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 hover:bg-neutral-200'
            }`}
          >
            All Categories ({services.length})
          </button>
          {categories.map((cat) => {
            const count = services.filter((s) => String(s.categoryId) === String(cat.id)).length;
            const isSelected = String(selectedCategoryFilter) === String(cat.id);
            return (
              <button
                key={cat.id}
                type="button"
                onClick={() => {
                  setSelectedCategoryFilter(String(cat.id));
                  setCurrentPage(1);
                }}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-colors cursor-pointer ${
                  isSelected
                    ? 'bg-neutral-950 text-white dark:bg-white dark:text-neutral-950'
                    : 'bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 hover:bg-neutral-200'
                }`}
              >
                <span>{cat.name}</span>
                <span className="text-[10px] opacity-75 font-mono">({count})</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Search & Filters Bar */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-3 bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 rounded-lg p-3">
        <div className="relative w-full md:w-80">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-neutral-400" />
          <input
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
            placeholder="Search service name, ID, code..."
            className="w-full h-9 pl-9 pr-3 text-xs bg-neutral-50 dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-800 rounded-md focus:outline-none focus:ring-1 focus:ring-neutral-950"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto">
          <div className="flex items-center gap-1.5 text-xs text-neutral-500">
            <Filter className="h-3.5 w-3.5" />
            <span>Rate Filter:</span>
          </div>
          <select
            value={rateFilter}
            onChange={(e) => {
              setRateFilter(e.target.value as 'ALL' | 'CONFIGURED' | 'BLANK');
              setCurrentPage(1);
            }}
            className="h-9 px-3 text-xs bg-neutral-50 dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-800 rounded-md"
          >
            <option value="ALL">All Rates</option>
            <option value="CONFIGURED">Configured (Charge &gt; 0)</option>
            <option value="BLANK">Blank / Unconfigured</option>
          </select>
        </div>
      </div>

      {/* Main Grid: Service List (Left) & Configuration / Form Builder (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Service List (5 Cols) */}
        <div className="lg:col-span-5 bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-neutral-200 dark:border-neutral-800 flex items-center justify-between">
            <span className="text-xs font-semibold text-neutral-700 dark:text-neutral-300">
              Services Catalog ({filteredServices.length})
            </span>
            <span className="text-[11px] font-mono text-neutral-500">
              Page {currentPage} of {totalPages}
            </span>
          </div>

          <div className="divide-y divide-neutral-100 dark:divide-neutral-800 max-h-[600px] overflow-y-auto">
            {loading ? (
              <div className="p-6 text-xs text-neutral-500 text-center">Loading services...</div>
            ) : paginatedServices.length === 0 ? (
              <div className="p-6 text-xs text-neutral-500 text-center">No services found matching filters.</div>
            ) : (
              paginatedServices.map((svc) => {
                const isSelected = selectedService?.serviceId === svc.serviceId;
                return (
                  <div
                    key={svc.serviceId}
                    onClick={() => selectService(svc)}
                    className={`p-4 cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-neutral-50 dark:bg-neutral-800/60 border-l-2 border-neutral-950 dark:border-white'
                        : 'hover:bg-neutral-50/70 dark:hover:bg-neutral-800/30'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="font-mono text-[11px] text-neutral-500">
                          {svc.serviceId} · {svc.categoryName}
                        </div>
                        <div className="font-semibold text-sm text-neutral-950 dark:text-white mt-0.5">
                          {svc.name}
                        </div>
                      </div>
                      <div className="text-right shrink-0 flex items-center gap-2">
                        <div>
                          <div className="font-mono text-xs font-semibold text-neutral-950 dark:text-white">
                            {formatCurrency(svc.customerCharge)}
                          </div>
                          <div className="font-mono text-[10px] text-emerald-700 dark:text-emerald-400">
                            Prof: {formatCurrency(svc.profitAmount)}
                          </div>
                        </div>
                        {isAdmin && (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              promptDeleteService(svc);
                            }}
                            className="p-1.5 text-neutral-400 hover:text-red-600 dark:hover:text-red-400 rounded transition-colors cursor-pointer"
                            title={`Delete service ${svc.serviceId}`}
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        )}
                      </div>
                    </div>

                    <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[11px] text-neutral-500">
                      <span>
                        Form v{svc.currentFormVersion} · {svc.requiredDocuments.length} docs · SLA {svc.sla.expectedDays}d
                      </span>
                      {svc.status === 'Active' && svc.availability === 'Available' && (
                        <Button
                          size="sm"
                          variant="primary"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenApplyWorkflow(svc);
                          }}
                        >
                          Apply Service
                        </Button>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Pagination Footer */}
          {totalPages > 1 && (
            <div className="px-4 py-3 border-t border-neutral-200 dark:border-neutral-800 flex items-center justify-between text-xs">
              <Button
                size="sm"
                variant="outline"
                disabled={currentPage === 1}
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              >
                Previous
              </Button>
              <span className="font-mono text-neutral-500">
                {currentPage} / {totalPages}
              </span>
              <Button
                size="sm"
                variant="outline"
                disabled={currentPage === totalPages}
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              >
                Next
              </Button>
            </div>
          )}
        </div>

        {/* Selected Service Configuration & Form Builder (7 Cols) */}
        <div className="lg:col-span-7 bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 rounded-lg p-5 space-y-4">
          {!selectedService ? (
            <div className="text-xs text-neutral-500 text-center py-12">
              Select a service from the left catalog to inspect or configure its dynamic form, required documents, SLA, and pricing.
            </div>
          ) : (
            <>
              {/* Header summary */}
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-neutral-200 dark:border-neutral-800 pb-3">
                <div>
                  <div className="font-mono text-xs text-neutral-500">
                    {selectedService.serviceId} · {selectedService.serviceCode} · {selectedService.categoryName}
                  </div>
                  <h3 className="text-base font-bold text-neutral-950 dark:text-white">
                    {selectedService.name}
                  </h3>
                </div>
                <div className="flex items-center gap-2">
                  {isAdmin && (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => promptDeleteService(selectedService)}
                      className="text-red-600 border-red-200 hover:bg-red-50 dark:border-red-900 dark:hover:bg-red-950/40"
                      icon={<Trash2 className="h-3.5 w-3.5" />}
                    >
                      Delete Service
                    </Button>
                  )}
                  <Button
                    size="sm"
                    variant="primary"
                    onClick={() => handleOpenApplyWorkflow(selectedService)}
                  >
                    Apply Service Workflow
                  </Button>
                </div>
              </div>

              {/* Sub-tabs */}
              <div className="flex flex-wrap gap-1.5 text-xs">
                {(
                  [
                    ['form', 'Dynamic Form Builder', FileText],
                    ['docs', 'Required Documents', Layers],
                    ['sla', 'SLA & Processing', Settings2],
                    ['automation', 'Automation Rules', Zap],
                    ['pricing', 'Pricing & Status', Edit3],
                  ] as const
                ).map(([key, label, IconComp]) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setActiveSubTab(key)}
                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border cursor-pointer ${
                      activeSubTab === key
                        ? 'bg-neutral-950 text-white border-neutral-950 dark:bg-white dark:text-neutral-950 font-medium'
                        : 'border-neutral-200 dark:border-neutral-700 text-neutral-700 dark:text-neutral-300 hover:bg-neutral-100'
                    }`}
                  >
                    <IconComp className="h-3.5 w-3.5" />
                    <span>{label}</span>
                  </button>
                ))}
              </div>

              {/* Tab 1: Dynamic Form Builder */}
              {activeSubTab === 'form' && (
                <div className="space-y-4 text-xs">
                  <div className="flex items-center justify-between bg-neutral-50 dark:bg-neutral-950 p-3 rounded border border-neutral-200 dark:border-neutral-800">
                    <div>
                      <span className="font-semibold">Published Version: v{selectedService.currentFormVersion}</span>
                      <p className="text-neutral-500 text-[11px] mt-0.5">
                        {draftFields.length} field(s) configured. Publishing a new version preserves all historical applications.
                      </p>
                    </div>
                    {isAdmin && (
                      <Button
                        type="button"
                        size="sm"
                        variant="primary"
                        loading={publishingForm}
                        onClick={handlePublishFormVersion}
                        icon={<Check className="h-3.5 w-3.5" />}
                      >
                        Publish New Version (v{selectedService.currentFormVersion + 1})
                      </Button>
                    )}
                  </div>

                  <div className="divide-y divide-neutral-100 dark:divide-neutral-800 border border-neutral-200 dark:border-neutral-800 rounded overflow-hidden">
                    {draftFields.map((f, idx) => (
                      <div key={`${f.fieldKey}-${idx}`} className="p-3 flex items-center justify-between gap-2 bg-white dark:bg-neutral-900">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-neutral-400">#{idx + 1}</span>
                            <span className="font-semibold text-neutral-950 dark:text-white">{f.label}</span>
                            {f.required && <span className="text-[10px] bg-blue-100 text-blue-800 px-1.5 py-0.5 rounded font-mono">Required</span>}
                          </div>
                          <div className="font-mono text-[11px] text-neutral-500 mt-0.5">
                            Key: {f.fieldKey} · Type: {f.fieldType}
                          </div>
                          {f.options && f.options.length > 0 && (
                            <div className="text-[11px] text-neutral-500 mt-1">
                              Options: {f.options.join(', ')}
                            </div>
                          )}
                        </div>
                        {isAdmin && (
                          <button
                            type="button"
                            onClick={() => setDraftFields((prev) => prev.filter((_, i) => i !== idx))}
                            className="text-red-600 hover:text-red-800 p-1 cursor-pointer"
                            title="Remove Field"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </div>
                    ))}
                  </div>

                  {isAdmin && (
                    <div className="bg-neutral-50 dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-800 rounded p-3 space-y-3">
                      <div className="font-semibold text-neutral-950 dark:text-white">Add Dynamic Form Field</div>
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                        <input
                          value={newField.label}
                          onChange={(e) => setNewField({ ...newField, label: e.target.value })}
                          placeholder="Field Label (e.g. Full Name)"
                          className="h-8 px-2 border rounded bg-white dark:bg-neutral-900 text-xs"
                        />
                        <select
                          value={newField.fieldType}
                          onChange={(e) => setNewField({ ...newField, fieldType: e.target.value as DynamicFieldType })}
                          className="h-8 px-2 border rounded bg-white dark:bg-neutral-900 text-xs"
                        >
                          {ALL_FIELD_TYPES.map((t) => (
                            <option key={t.value} value={t.value}>{t.label}</option>
                          ))}
                        </select>
                        <label className="flex items-center gap-1.5">
                          <input
                            type="checkbox"
                            checked={newField.required}
                            onChange={(e) => setNewField({ ...newField, required: e.target.checked })}
                          />
                          Mandatory / Required
                        </label>
                      </div>
                      {['dropdown', 'radio', 'multi_select'].includes(newField.fieldType) && (
                        <input
                          value={newField.optionsCsv}
                          onChange={(e) => setNewField({ ...newField, optionsCsv: e.target.value })}
                          placeholder="Comma-separated options (e.g., Option A, Option B, Option C)"
                          className="w-full h-8 px-2 border rounded bg-white dark:bg-neutral-900 text-xs"
                        />
                      )}
                      <Button size="sm" variant="outline" onClick={handleAddField} icon={<Plus className="h-3 w-3" />}>
                        Append Field to Draft
                      </Button>
                    </div>
                  )}
                </div>
              )}

              {/* Tab 2: Required Documents */}
              {activeSubTab === 'docs' && (
                <div className="space-y-3 text-xs">
                  <div className="font-semibold text-neutral-950 dark:text-white">Configured Required &amp; Optional Documents Checklist</div>
                  <div className="divide-y divide-neutral-100 dark:divide-neutral-800 border border-neutral-200 dark:border-neutral-800 rounded overflow-hidden">
                    {selectedService.requiredDocuments.map((d, i) => (
                      <div key={i} className="p-3 flex items-center justify-between bg-white dark:bg-neutral-900">
                        <div>
                          <div className="font-semibold">{typeof d === 'string' ? d : d.label}</div>
                          <div className="text-neutral-500 text-[11px] mt-0.5">
                            Category: {typeof d === 'object' && d.category ? d.category : 'Identity / Support'} · Mandatory Document Checklist
                          </div>
                        </div>
                        <span className="font-mono text-[10px] bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded">Active</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Tab 3: SLA & Processing */}
              {activeSubTab === 'sla' && (
                <div className="border border-neutral-200 dark:border-neutral-800 rounded p-4 text-xs space-y-3 bg-neutral-50 dark:bg-neutral-950">
                  <div className="font-semibold text-neutral-950 dark:text-white">SLA &amp; Processing Targets</div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>Processing Mode: <span className="font-semibold">{selectedService.sla.processingMode}</span></div>
                    <div>Target Window: <span className="font-semibold">{selectedService.sla.minDays}–{selectedService.sla.maxDays} days (Expected {selectedService.sla.expectedDays}d)</span></div>
                    <div>Calculation Type: <span className="font-semibold">{selectedService.sla.dayType} days</span></div>
                    <div>Start Event: <span className="font-semibold">{selectedService.sla.startEvent}</span></div>
                  </div>
                  <div>
                    Auto-Pause Statuses: <span className="font-mono text-[11px] bg-neutral-200 dark:bg-neutral-800 px-2 py-0.5 rounded">{selectedService.sla.pauseOnStatuses.join(', ')}</span>
                  </div>
                </div>
              )}

              {/* Tab 4: Automation Rules */}
              {activeSubTab === 'automation' && (
                <div className="space-y-2 text-xs">
                  <div className="font-semibold text-neutral-950 dark:text-white">Configured Service Automation Rules</div>
                  {selectedService.automationRules.length === 0 ? (
                    <p className="text-neutral-500 p-4 border rounded border-dashed text-center">No service automation rules configured.</p>
                  ) : (
                    selectedService.automationRules.map((r) => (
                      <div key={r.id} className="border border-neutral-200 dark:border-neutral-800 rounded p-3 flex items-center justify-between">
                        <div>
                          <div className="font-semibold">{r.name}</div>
                          <div className="text-neutral-500 font-mono text-[11px] mt-0.5">
                            Trigger: {r.trigger} → Action: {r.actionType} ({r.actionParam})
                          </div>
                        </div>
                        <span className="font-mono text-[11px]">Executions: {r.executionCount}</span>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Tab 5: Pricing & Status */}
              {activeSubTab === 'pricing' && isAdmin && (
                <div className="space-y-4 text-xs border border-neutral-200 dark:border-neutral-800 rounded p-4 bg-neutral-50 dark:bg-neutral-950">
                  <div className="font-semibold text-neutral-950 dark:text-white">Service Pricing &amp; Profit Engine</div>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div>
                      <label className="block font-medium mb-1">Customer Charge (₹)</label>
                      <input
                        type="number"
                        value={editCharge}
                        onChange={(e) => setEditCharge(Number(e.target.value))}
                        className="w-full h-9 px-3 border rounded font-mono bg-white dark:bg-neutral-900 text-xs"
                      />
                    </div>
                    <div>
                      <label className="block font-medium mb-1">Service Cost (₹)</label>
                      <input
                        type="number"
                        value={editCost}
                        onChange={(e) => setEditCost(Number(e.target.value))}
                        className="w-full h-9 px-3 border rounded font-mono bg-white dark:bg-neutral-900 text-xs"
                      />
                    </div>
                    <div>
                      <label className="block font-medium mb-1">Calculated Profit (₹)</label>
                      <div className="h-9 px-3 border rounded flex items-center font-mono font-bold bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300">
                        {formatCurrency(editCharge - editCost)}
                      </div>
                    </div>
                  </div>
                  <div>
                    <label className="block font-medium mb-1">Service Status</label>
                    <select
                      value={editStatus}
                      onChange={(e) => setEditStatus(e.target.value as ErpServiceItem['status'])}
                      className="h-9 px-3 border rounded bg-white dark:bg-neutral-900 text-xs w-full sm:w-60"
                    >
                      <option value="Active">Active</option>
                      <option value="Inactive">Inactive</option>
                      <option value="Temporarily Suspended">Temporarily Suspended</option>
                      <option value="Archived">Archived</option>
                    </select>
                  </div>
                  <Button type="button" size="sm" variant="primary" loading={savingPricing} onClick={handleSavePricingAndStatus}>
                    Save Service Pricing &amp; Status
                  </Button>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {/* Apply Service Workflow Modal */}
      <Modal isOpen={applyModalOpen} onClose={() => setApplyModalOpen(false)} title={`Apply Service: ${applyingService?.name ?? ''}`}>
        <form onSubmit={handleExecuteApplyService} className="space-y-4 text-xs" noValidate>
          {applyError && (
            <div role="alert" className="px-3 py-2 rounded border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300">
              {applyError}
            </div>
          )}
          <div className="bg-neutral-50 dark:bg-neutral-950 p-3 rounded border border-neutral-200 dark:border-neutral-800">
            <div className="font-semibold text-neutral-950 dark:text-white">Customer Information</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-2">
              <div>
                <label className="block font-medium mb-1">Customer Full Name *</label>
                <input
                  required
                  value={applyCustName}
                  onChange={(e) => setApplyCustName(e.target.value)}
                  placeholder="Enter customer full name..."
                  className="w-full h-9 px-3 border rounded bg-white dark:bg-neutral-900 text-xs"
                />
              </div>
              <div>
                <label className="block font-medium mb-1">Mobile Number (10 digits) *</label>
                <input
                  required
                  value={applyCustMobile}
                  onChange={(e) => setApplyCustMobile(e.target.value)}
                  placeholder="9830001122"
                  className="w-full h-9 px-3 border rounded font-mono bg-white dark:bg-neutral-900 text-xs"
                />
              </div>
            </div>
            <div className="mt-2">
              <label className="block font-medium mb-1">Village / Locality</label>
              <input
                value={applyVillage}
                onChange={(e) => setApplyVillage(e.target.value)}
                placeholder="Mamudpur"
                className="w-full h-9 px-3 border rounded bg-white dark:bg-neutral-900 text-xs"
              />
            </div>
          </div>

          {applyingService && (
            <div className="space-y-3">
              <div className="font-semibold text-neutral-950 dark:text-white">Dynamic Form Inputs &amp; Required Checklist</div>
              <div className="p-3 border border-neutral-200 dark:border-neutral-800 rounded bg-white dark:bg-neutral-900 space-y-3">
                {applyingService.formVersions
                  .find((v) => v.versionNo === applyingService.currentFormVersion)
                  ?.fields.map((field) => (
                    <div key={field.fieldKey}>
                      <label className="block font-medium mb-1">
                        {field.label} {field.required && <span className="text-red-500">*</span>}
                      </label>
                      <input
                        required={field.required}
                        value={applyFormData[field.fieldKey] ?? ''}
                        onChange={(e) =>
                          setApplyFormData({ ...applyFormData, [field.fieldKey]: e.target.value })
                        }
                        placeholder={`Enter ${field.label}...`}
                        className="w-full h-9 px-3 border rounded bg-neutral-50 dark:bg-neutral-950 text-xs"
                      />
                    </div>
                  ))}
              </div>
            </div>
          )}

          <div className="flex justify-end gap-2 pt-2 border-t border-neutral-200 dark:border-neutral-800">
            <Button type="button" size="sm" variant="outline" onClick={() => setApplyModalOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" size="sm" variant="primary" disabled={submittingApp}>
              {submittingApp ? 'Submitting Application...' : 'Submit & Generate Application No'}
            </Button>
          </div>
        </form>
      </Modal>

      {/* Add Master Service Modal */}
      <Modal
        isOpen={newServiceOpen}
        onClose={() => {
          setSrvError(null);
          setNewServiceOpen(false);
        }}
        title="Create Master Service"
      >
        <form onSubmit={handleCreateService} className="space-y-3 text-xs" noValidate>
          {srvError && (
            <div role="alert" className="px-3 py-2 rounded border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300">
              {srvError}
            </div>
          )}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <div>
              <label className="block font-medium mb-1">Service Name *</label>
              <input
                required
                value={srvForm.name}
                onChange={(e) => {
                  setSrvError(null);
                  setSrvForm({ ...srvForm, name: e.target.value });
                }}
                placeholder="e.g. Income Certificate"
                className="w-full h-9 px-3 border rounded bg-white dark:bg-neutral-900 text-xs"
              />
            </div>
            <div>
              <label className="block font-medium mb-1">Service Code (Optional)</label>
              <input
                value={srvForm.serviceCode}
                onChange={(e) => setSrvForm({ ...srvForm, serviceCode: e.target.value })}
                placeholder="Auto-generated if blank"
                className="w-full h-9 px-3 border rounded font-mono bg-white dark:bg-neutral-900 text-xs"
              />
            </div>
          </div>
          <div>
            <label className="block font-medium mb-1">Category</label>
            <select
              value={srvForm.categoryId}
              onChange={(e) => setSrvForm({ ...srvForm, categoryId: Number(e.target.value) })}
              className="w-full h-9 px-3 border rounded bg-white dark:bg-neutral-900 text-xs"
            >
              {categories.map((c) => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
          </div>
          <div className="grid grid-cols-3 gap-2">
            <div>
              <label className="block font-medium mb-1">Charge (₹)</label>
              <input
                type="number"
                value={srvForm.customerCharge}
                onChange={(e) => setSrvForm({ ...srvForm, customerCharge: Number(e.target.value) })}
                className="w-full h-9 px-2 border rounded font-mono bg-white dark:bg-neutral-900 text-xs"
              />
            </div>
            <div>
              <label className="block font-medium mb-1">Cost (₹)</label>
              <input
                type="number"
                value={srvForm.serviceCost}
                onChange={(e) => setSrvForm({ ...srvForm, serviceCost: Number(e.target.value) })}
                className="w-full h-9 px-2 border rounded font-mono bg-white dark:bg-neutral-900 text-xs"
              />
            </div>
            <div>
              <label className="block font-medium mb-1">SLA Days</label>
              <input
                type="number"
                value={srvForm.expectedDays}
                onChange={(e) => setSrvForm({ ...srvForm, expectedDays: Number(e.target.value) })}
                className="w-full h-9 px-2 border rounded font-mono bg-white dark:bg-neutral-900 text-xs"
              />
            </div>
          </div>
          <textarea
            rows={2}
            value={srvForm.description}
            onChange={(e) => setSrvForm({ ...srvForm, description: e.target.value })}
            placeholder="Service description..."
            className="w-full p-2 border rounded bg-white dark:bg-neutral-900 text-xs"
          />
          <div className="flex justify-end gap-2">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => {
                setSrvError(null);
                setNewServiceOpen(false);
              }}
            >
              Cancel
            </Button>
            <Button type="submit" size="sm" variant="primary" loading={savingSrv}>
              Create Service
            </Button>
          </div>
        </form>
      </Modal>

      {/* Add Category Modal */}
      <Modal
        isOpen={newCatOpen}
        onClose={() => {
          setCatError(null);
          setNewCatOpen(false);
        }}
        title="Add Service Category"
      >
        <form onSubmit={handleCreateCategory} className="space-y-3 text-xs" noValidate>
          {catError && (
            <div role="alert" className="px-3 py-2 rounded border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300">
              {catError}
            </div>
          )}
          <div>
            <label className="block font-medium mb-1">Category Name *</label>
            <input
              required
              value={catForm.name}
              onChange={(e) => {
                setCatError(null);
                setCatForm({ ...catForm, name: e.target.value });
              }}
              placeholder="e.g. Citizen & KYC Services"
              className="w-full h-9 px-3 border rounded bg-white dark:bg-neutral-900 text-xs"
            />
          </div>
          <div>
            <label className="block font-medium mb-1">Description</label>
            <input
              value={catForm.description}
              onChange={(e) => setCatForm({ ...catForm, description: e.target.value })}
              placeholder="Category scope description..."
              className="w-full h-9 px-3 border rounded bg-white dark:bg-neutral-900 text-xs"
            />
          </div>
          <div className="flex justify-end gap-2">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => {
                setCatError(null);
                setNewCatOpen(false);
              }}
            >
              Cancel
            </Button>
            <Button type="submit" size="sm" variant="primary" loading={savingCat}>
              Create Category
            </Button>
          </div>
        </form>
      </Modal>

      {/* Delete Service Confirmation Modal */}
      <Modal
        isOpen={deleteServiceModalOpen}
        onClose={() => setDeleteServiceModalOpen(false)}
        title={`Confirm Service Deletion: ${serviceToDelete?.serviceId ?? ''}`}
      >
        <div className="space-y-4 text-xs">
          <p className="text-neutral-700 dark:text-neutral-300 leading-relaxed">
            Are you sure you want to delete service <span className="font-semibold">{serviceToDelete?.name}</span> ({serviceToDelete?.serviceId} / {serviceToDelete?.serviceCode})? This will instantly remove it from the MUN COMPUTER service catalog and update the database and Firestore.
          </p>
          <div className="flex justify-end gap-2 pt-3 border-t border-neutral-200 dark:border-neutral-800">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => setDeleteServiceModalOpen(false)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              size="sm"
              variant="primary"
              loading={deletingService}
              onClick={handleExecuteDeleteService}
              className="bg-red-600 hover:bg-red-700 text-white"
            >
              Confirm & Delete Service
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
