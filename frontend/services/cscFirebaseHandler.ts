import {
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocs,
  query,
  serverTimestamp,
  setDoc,
  updateDoc,
  where,
} from 'firebase/firestore';
import {
  ALL_UNIT_TYPES,
  CscAdminDashboardKpis,
  CscApplicationStatus,
  CscCategory,
  CscCustomerExtended,
  CscDocumentRecord,
  CscOrderItemSnapshot,
  CscOrderRecord,
  CscPaymentEntry,
  CscPaymentStatus,
  CscRateHistoryEntry,
  CscService,
  GrievanceRecord,
  GrievanceStatus,
  PvcOrder,
  PvcOrderItem,
  PvcRateSlab,
  UnitType,
  WholesaleShop,
} from '../../shared/cscTypes';
import {
  buildInitialCscCategories,
  buildInitialCscServices,
  buildInitialIndividualPvcSlabs,
  buildInitialPvcCardTypes,
} from '../../shared/cscCatalogSeed';
import { ApiResponseEnvelope, UserProfile } from '../modules/types';
import { OperationType, handleFirestoreError, requireFirebase, timestampToIso } from './firebase';

const FORBIDDEN_KEY_RE =
  /^(otp|aadhaar_?otp|upi_?pin|atm_?pin|pin|cvv|card_?cvv|bank_?password|netbanking_?password|mpin)$/i;

function assertSafePayload(payload: unknown): void {
  if (!payload || typeof payload !== 'object') return;
  if (Array.isArray(payload)) {
    payload.forEach(assertSafePayload);
    return;
  }
  for (const [k, v] of Object.entries(payload as Record<string, unknown>)) {
    if (FORBIDDEN_KEY_RE.test(k.trim())) {
      throw new Error(`Security Policy Violation: Field '${k}' must NEVER be stored.`);
    }
    if (v && typeof v === 'object') assertSafePayload(v);
  }
}

function maskAadhaarStr(raw?: string): string {
  if (!raw) return '';
  return raw.replace(/\b(\d{4})[-\s]?(\d{4})[-\s]?(\d{4})\b/g, 'XXXX-XXXX-$3');
}

function round2(n: number): number {
  return Math.round((n + Number.EPSILON) * 100) / 100;
}

function computePayStatus(total: number, paid: number, refunded = 0): CscPaymentStatus {
  if (refunded > 0 && refunded >= paid && paid > 0) return 'Refunded';
  const net = round2(Math.max(0, paid - refunded));
  if (total <= 0) return net > 0 ? 'Paid' : 'Unpaid';
  if (net >= round2(total)) return 'Paid';
  if (net > 0) return 'Partial';
  return 'Unpaid';
}

function ok<T>(data: T, message = 'OK'): ApiResponseEnvelope<T> {
  return {
    success: true,
    message,
    data,
    meta: { timestamp: new Date().toISOString() },
  };
}

function errHttp(message: string, status = 400): never {
  const err = new Error(message) as Error & { status?: number };
  err.status = status;
  throw err;
}

async function listScopedDocs(
  colName: string,
  uid: string,
  isBootAdmin: boolean,
  isCustomer = false
): Promise<Array<Record<string, any>>> {
  const { db } = requireFirebase();
  try {
    const colRef = collection(db, colName);
    if (isBootAdmin) {
      const snap = await getDocs(colRef);
      return snap.docs.map((d) => ({ ...(d.data() as Record<string, any>), _docId: d.id }));
    }
    const q = isCustomer
      ? query(colRef, where('customerUid', '==', uid))
      : query(colRef, where('createdByUid', '==', uid));
    const snap = await getDocs(q);
    return snap.docs.map((d) => ({ ...(d.data() as Record<string, any>), _docId: d.id }));
  } catch (err) {
    handleFirestoreError(err, OperationType.LIST, colName);
  }
}

async function listCatalogDocs(colName: string): Promise<Array<Record<string, any>>> {
  const { db } = requireFirebase();
  try {
    const snap = await getDocs(query(collection(db, colName), where('active', 'in', [true, false])));
    return snap.docs.map((d) => ({ ...(d.data() as Record<string, any>), _docId: d.id }));
  } catch (err) {
    handleFirestoreError(err, OperationType.LIST, colName);
  }
}

async function loadMergedCategories(): Promise<CscCategory[]> {
  const base = buildInitialCscCategories();
  const map = new Map(base.map((c) => [c.id, c]));
  const overrides = await listCatalogDocs('cscCustomCategories');
  for (const raw of overrides) {
    const id = String(raw.id || raw._docId);
    const prev = map.get(id);
    map.set(id, {
      ...(prev ?? {
        id,
        code: String(raw.code || id),
        name: String(raw.name || ''),
        icon: 'FolderKanban',
        description: '',
        displayOrder: map.size + 1,
        active: true,
        moduleTag: 'GENERAL',
        createdAt: timestampToIso(raw.createdAt),
        updatedAt: timestampToIso(raw.updatedAt),
      }),
      code: String(raw.code ?? prev?.code ?? id),
      name: String(raw.name ?? prev?.name ?? ''),
      description: String(raw.description ?? prev?.description ?? ''),
      active: Boolean(raw.active ?? true),
      displayOrder: Number(raw.displayOrder ?? prev?.displayOrder ?? 99),
      noticeText: raw.noticeText ? String(raw.noticeText) : prev?.noticeText,
      updatedAt: timestampToIso(raw.updatedAt),
    });
  }
  return Array.from(map.values()).sort((a, b) => a.displayOrder - b.displayOrder);
}

async function loadMergedServices(): Promise<CscService[]> {
  const base = buildInitialCscServices();
  const map = new Map(base.map((s) => [s.id, s]));
  const overrides = await listCatalogDocs('cscServiceOverrides');
  for (const raw of overrides) {
    const id = String(raw.serviceId || raw._docId);
    const prev = map.get(id);
    map.set(id, {
      id,
      code: String(raw.code ?? prev?.code ?? id),
      categoryId: String(raw.categoryId ?? prev?.categoryId ?? 'CAT-18'),
      categoryName: String(raw.categoryName ?? prev?.categoryName ?? 'General'),
      subGroup: raw.subGroup ? String(raw.subGroup) : prev?.subGroup,
      name: String(raw.name ?? prev?.name ?? id),
      description: String(raw.description ?? prev?.description ?? ''),
      serviceCharge:
        raw.serviceCharge !== undefined && raw.serviceCharge !== null ? Number(raw.serviceCharge) : null,
      govtFee: raw.govtFee !== undefined && raw.govtFee !== null ? Number(raw.govtFee) : null,
      totalAmount:
        raw.totalAmount !== undefined && raw.totalAmount !== null ? Number(raw.totalAmount) : null,
      unitType: raw.unitType ? (String(raw.unitType) as UnitType) : null,
      rateConfigured: Boolean(raw.rateConfigured),
      effectiveDate: raw.effectiveDate ? String(raw.effectiveDate) : null,
      requiredDocuments: Array.isArray(raw.requiredDocuments)
        ? raw.requiredDocuments.map(String)
        : prev?.requiredDocuments ?? ['Applicant ID Proof'],
      availability:
        raw.availability === 'Unavailable' ? 'Unavailable' : prev?.availability ?? 'Available',
      active: Boolean(raw.active ?? prev?.active ?? true),
      moduleTag: (raw.moduleTag as CscService['moduleTag']) ?? prev?.moduleTag ?? 'GENERAL',
      createdAt: timestampToIso(raw.createdAt, prev?.createdAt),
      updatedAt: timestampToIso(raw.updatedAt),
      updatedBy: String(raw.updatedBy || 'ADMIN'),
    });
  }
  return Array.from(map.values());
}

async function loadMergedPvcSlabs(): Promise<PvcRateSlab[]> {
  const baseInd = buildInitialIndividualPvcSlabs();
  const map = new Map(baseInd.map((s) => [s.id, s]));
  const docs = await listCatalogDocs('pvcSlabs');
  for (const raw of docs) {
    const id = String(raw.id || raw._docId);
    map.set(id, {
      id,
      mode: raw.mode === 'WHOLESALE' ? 'WHOLESALE' : 'INDIVIDUAL',
      minQty: Number(raw.minQty),
      maxQty: Number(raw.maxQty),
      ratePerCard: Number(raw.ratePerCard),
      active: Boolean(raw.active ?? true),
      createdAt: timestampToIso(raw.createdAt),
      updatedAt: timestampToIso(raw.updatedAt),
      updatedBy: String(raw.updatedBy || 'ADMIN'),
    });
  }
  return Array.from(map.values());
}

export async function handleCscFirebaseRoute<T>(
  pathname: string,
  method: string,
  searchParams: URLSearchParams,
  body: Record<string, unknown>,
  uid: string,
  currentProfile: UserProfile,
  isBootAdmin: boolean
): Promise<ApiResponseEnvelope<T> | null> {
  const { db } = requireFirebase();

  try {
    assertSafePayload(body);
  } catch (e) {
    errHttp(e instanceof Error ? e.message : 'Forbidden field.', 422);
  }

  const isCustomer = currentProfile.role === 'CUSTOMER';
  const isAdmin = currentProfile.role === 'ADMIN' || isBootAdmin;

  // =========================================================================
  // WORKSPACE BOOTSTRAP
  // =========================================================================
  if (pathname === '/api/csc/workspace' && method === 'GET') {
    const [categories, services, pvcSlabs, shopsRaw, ordersRaw, pvcOrdersRaw, grievancesRaw, custRaw] =
      await Promise.all([
        loadMergedCategories(),
        loadMergedServices(),
        isCustomer ? Promise.resolve([]) : loadMergedPvcSlabs(),
        isCustomer ? Promise.resolve([]) : listScopedDocs('wholesaleShops', uid, isBootAdmin, false),
        listScopedDocs('cscOrders', uid, isBootAdmin, isCustomer),
        listScopedDocs('pvcOrders', uid, isBootAdmin, isCustomer),
        listScopedDocs('cscGrievances', uid, isBootAdmin, isCustomer),
        isCustomer ? Promise.resolve([]) : listScopedDocs('customers', uid, isBootAdmin, false),
      ]);

    const orders = ordersRaw.map((o) => ({
      ...(o as unknown as CscOrderRecord),
      createdAt: timestampToIso(o.createdAt),
      updatedAt: timestampToIso(o.updatedAt),
    }));
    const pvcOrders = pvcOrdersRaw.map((o) => ({
      ...(o as unknown as PvcOrder),
      createdAt: timestampToIso(o.createdAt),
      updatedAt: timestampToIso(o.updatedAt),
    }));
    const grievances = grievancesRaw.map((g) => ({
      ...(g as unknown as GrievanceRecord),
      createdAt: timestampToIso(g.createdAt),
      updatedAt: timestampToIso(g.updatedAt),
    }));
    const wholesaleShops = shopsRaw.map((s) => ({
      ...(s as unknown as WholesaleShop),
      createdAt: timestampToIso(s.createdAt),
      updatedAt: timestampToIso(s.updatedAt),
    }));
    const customers: CscCustomerExtended[] = custRaw.map((c) => ({
      customerId: String(c.customerId || ''),
      fullName: String(c.fullName || ''),
      mobile: String(c.mobile || ''),
      altMobile: String(c.whatsapp || ''),
      email: String(c.email || ''),
      address: String(c.presentAddress || c.village || ''),
      district: String(c.district || ''),
      blockOrMunicipality: String(c.policeStation || ''),
      aadhaarMasked: c.aadhaarMasked ? String(c.aadhaarMasked) : undefined,
      registrationDate: timestampToIso(c.createdAt).slice(0, 10),
      remarks: '',
      accountStatus: (c.status as CscCustomerExtended['accountStatus']) || 'Active',
      createdAt: timestampToIso(c.createdAt),
      updatedAt: timestampToIso(c.updatedAt),
    }));

    return ok({
      categories,
      servicesCount: services.length,
      pvcCardTypes: buildInitialPvcCardTypes(),
      pvcSlabs,
      wholesaleShops,
      customers,
      orders,
      pvcOrders,
      grievances,
      paymentMethods: [
        { id: 'PM-CASH', name: 'Cash', active: true },
        { id: 'PM-UPI', name: 'UPI', active: true },
        { id: 'PM-BANK', name: 'Bank Transfer', active: true },
      ],
      effectivePermissions: currentProfile.permissions ?? {},
      kpis: isCustomer
        ? null
        : computeKpisFromArrays(categories, services, customers, orders, pvcOrders, grievances),
    }) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/csc/dashboard-kpis' && method === 'GET') {
    if (isCustomer) errHttp('Forbidden.', 403);
    const [categories, services, ordersRaw, pvcRaw, grvRaw, custRaw] = await Promise.all([
      loadMergedCategories(),
      loadMergedServices(),
      listScopedDocs('cscOrders', uid, isBootAdmin),
      listScopedDocs('pvcOrders', uid, isBootAdmin),
      listScopedDocs('cscGrievances', uid, isBootAdmin),
      listScopedDocs('customers', uid, isBootAdmin),
    ]);
    return ok(
      computeKpisFromArrays(
        categories,
        services,
        custRaw,
        ordersRaw as unknown as CscOrderRecord[],
        pvcRaw as unknown as PvcOrder[],
        grvRaw as unknown as GrievanceRecord[],
        searchParams.get('fromDate') || undefined,
        searchParams.get('toDate') || undefined
      )
    ) as ApiResponseEnvelope<T>;
  }

  // =========================================================================
  // CATEGORIES & SERVICES + RATE MANAGER
  // =========================================================================
  if (pathname === '/api/csc/categories' && method === 'GET') {
    return ok(await loadMergedCategories()) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/csc/categories' && method === 'POST') {
    if (!isAdmin) errHttp('Only ADMIN can create categories.', 403);
    const name = String(body.name || '').trim();
    if (name.length < 2) errHttp('Category name must be at least 2 characters.', 422);
    const cats = await loadMergedCategories();
    const maxNum = cats.reduce((max, c) => {
      const m = c.id.match(/^CAT-(\d+)$/);
      return m ? Math.max(max, Number(m[1])) : max;
    }, cats.length);
    let nextNum = maxNum + 1;
    let id = `CAT-${String(nextNum).padStart(2, '0')}`;
    try {
      while ((await getDoc(doc(db, 'cscCustomCategories', id))).exists()) {
        nextNum += 1;
        id = `CAT-${String(nextNum).padStart(2, '0')}`;
      }
      const rawCode = String(body.code || '').trim().toUpperCase().replace(/[^A-Z0-9_-]+/g, '-').slice(0, 40);
      const code = rawCode.length >= 2 ? rawCode : id;
      const payload = {
        id,
        code,
        name: name.slice(0, 160),
        icon: 'FolderKanban',
        description: String(body.description || '').trim().slice(0, 500),
        displayOrder: nextNum,
        active: true,
        moduleTag: 'GENERAL',
        createdByUid: uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      };
      await setDoc(doc(db, 'cscCustomCategories', id), payload);
      return ok({ ...payload, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.CREATE, `cscCustomCategories/${id}`);
    }
  }

  if (pathname.startsWith('/api/csc/categories/') && method === 'PUT') {
    if (!isAdmin) errHttp('Only ADMIN can update categories.', 403);
    const catId = decodeURIComponent(pathname.split('/').pop() || '');
    const cats = await loadMergedCategories();
    const prev = cats.find((c) => c.id === catId);
    if (!prev) errHttp('Category not found.', 404);
    const nextName = body.name !== undefined ? String(body.name).trim() : prev.name;
    if (nextName.length < 2) errHttp('Category name must be at least 2 characters.', 422);
    const rawCode = body.code !== undefined ? String(body.code).trim().toUpperCase().replace(/[^A-Z0-9_-]+/g, '-').slice(0, 40) : prev.code;
    const nextCode = rawCode.length >= 2 ? rawCode : prev.code;
    const docRef = doc(db, 'cscCustomCategories', catId);
    try {
      const existingSnap = await getDoc(docRef);
      const merged = {
        id: catId,
        code: nextCode,
        name: nextName.slice(0, 160),
        icon: prev.icon || 'FolderKanban',
        description: body.description !== undefined ? String(body.description).trim().slice(0, 500) : prev.description,
        displayOrder: body.displayOrder !== undefined ? Number(body.displayOrder) : prev.displayOrder,
        active: body.active !== undefined ? Boolean(body.active) : prev.active,
        moduleTag: prev.moduleTag || 'GENERAL',
        createdByUid: existingSnap.exists() ? String(existingSnap.data().createdByUid) : uid,
        createdAt: existingSnap.exists() ? existingSnap.data().createdAt : serverTimestamp(),
        updatedAt: serverTimestamp(),
      };
      await setDoc(docRef, merged);
      return ok({ ...merged, updatedAt: new Date().toISOString() }) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `cscCustomCategories/${catId}`);
    }
  }

  if (pathname === '/api/csc/services' && method === 'GET') {
    let list = await loadMergedServices();
    const categoryId = searchParams.get('categoryId') || '';
    const moduleTag = searchParams.get('moduleTag') || '';
    const search = (searchParams.get('search') || '').trim().toLowerCase();
    const rateStatus = searchParams.get('rateStatus') || 'ALL';
    if (categoryId && categoryId !== 'ALL') list = list.filter((s) => s.categoryId === categoryId);
    if (moduleTag && moduleTag !== 'ALL') list = list.filter((s) => s.moduleTag === moduleTag);
    if (rateStatus === 'CONFIGURED') list = list.filter((s) => s.rateConfigured);
    else if (rateStatus === 'BLANK') list = list.filter((s) => !s.rateConfigured);
    if (search) {
      list = list.filter(
        (s) =>
          s.name.toLowerCase().includes(search) ||
          s.code.toLowerCase().includes(search) ||
          s.categoryName.toLowerCase().includes(search)
      );
    }
    return ok(list) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/csc/services' && method === 'POST') {
    if (!isAdmin) errHttp('Only ADMIN can create services.', 403);
    const name = String(body.name || '').trim();
    if (name.length < 2) errHttp('Service name must be at least 2 characters.', 422);
    const categories = await loadMergedCategories();
    const cat = categories.find((c) => c.id === String(body.categoryId || ''));
    if (!cat) errHttp('Selected category not found.', 404);
    let suffix = Number(Date.now().toString().slice(-6));
    let serviceId = `CSRV-C${suffix}`;
    try {
      while ((await getDoc(doc(db, 'cscServiceOverrides', serviceId))).exists()) {
        suffix += 1;
        serviceId = `CSRV-C${suffix}`;
      }
      const payload = {
        serviceId,
        code: `${cat.code}-${String(serviceId).slice(-4)}`,
        categoryId: cat.id,
        categoryName: cat.name,
        subGroup: body.subGroup ? String(body.subGroup).trim().slice(0, 120) : '',
        name: name.slice(0, 200),
        description: String(body.description || `${cat.name} — ${name}`).trim().slice(0, 500),
        serviceCharge: null,
        govtFee: null,
        totalAmount: null,
        unitType: null,
        rateConfigured: false,
        effectiveDate: null,
        requiredDocuments: Array.isArray(body.requiredDocuments)
          ? body.requiredDocuments.slice(0, 30).map((d) => String(d).slice(0, 120))
          : ['Applicant ID Proof'],
        availability: 'Available',
        active: true,
        moduleTag: cat.moduleTag || 'GENERAL',
        updatedBy: currentProfile.userId,
        updatedByUid: uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      };
      await setDoc(doc(db, 'cscServiceOverrides', serviceId), payload);
      return ok({ ...payload, id: serviceId, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.CREATE, `cscServiceOverrides/${serviceId}`);
    }
  }

  if (/^\/api\/csc\/services\/[^/]+\/duplicate$/.test(pathname) && method === 'POST') {
    if (!isAdmin) errHttp('Only ADMIN can duplicate services.', 403);
    const sourceId = decodeURIComponent(pathname.split('/')[4] || '');
    const services = await loadMergedServices();
    const src = services.find((s) => s.id === sourceId);
    if (!src) errHttp('Source service not found.', 404);
    let suffix = Number(Date.now().toString().slice(-6));
    let serviceId = `CSRV-D${suffix}`;
    try {
      while ((await getDoc(doc(db, 'cscServiceOverrides', serviceId))).exists()) {
        suffix += 1;
        serviceId = `CSRV-D${suffix}`;
      }
      const payload = {
        serviceId,
        code: `${src.code}-COPY`,
        categoryId: src.categoryId,
        categoryName: src.categoryName,
        subGroup: src.subGroup || '',
        name: `${src.name} (Copy)`.slice(0, 200),
        description: src.description,
        serviceCharge: null,
        govtFee: null,
        totalAmount: null,
        unitType: null,
        rateConfigured: false,
        effectiveDate: null,
        requiredDocuments: src.requiredDocuments.slice(0, 30),
        availability: src.availability,
        active: true,
        moduleTag: src.moduleTag,
        updatedBy: currentProfile.userId,
        updatedByUid: uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      };
      await setDoc(doc(db, 'cscServiceOverrides', serviceId), payload);
      return ok({ ...payload, id: serviceId, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.CREATE, `cscServiceOverrides/${serviceId}`);
    }
  }

  if (/^\/api\/csc\/services\/[^/]+$/.test(pathname) && method === 'PUT') {
    if (!isAdmin) errHttp('Only ADMIN can update services.', 403);
    const serviceId = decodeURIComponent(pathname.split('/')[4] || '');
    const services = await loadMergedServices();
    const svc = services.find((s) => s.id === serviceId);
    if (!svc) errHttp('Service not found.', 404);
    const nextName = body.name !== undefined ? String(body.name).trim() : svc.name;
    if (nextName.length < 2) errHttp('Service name must be at least 2 characters.', 422);
    const ref = doc(db, 'cscServiceOverrides', serviceId);
    try {
      const snap = await getDoc(ref);
      const updatedDoc = {
        serviceId,
        code: svc.code,
        categoryId: svc.categoryId,
        categoryName: svc.categoryName,
        subGroup: body.subGroup !== undefined ? String(body.subGroup).trim().slice(0, 120) : svc.subGroup || '',
        name: nextName.slice(0, 200),
        description: body.description !== undefined ? String(body.description).trim().slice(0, 500) : svc.description,
        serviceCharge: svc.serviceCharge,
        govtFee: svc.govtFee,
        totalAmount: svc.totalAmount,
        unitType: svc.unitType,
        rateConfigured: svc.rateConfigured,
        effectiveDate: svc.effectiveDate,
        requiredDocuments: Array.isArray(body.requiredDocuments)
          ? body.requiredDocuments.slice(0, 30).map((d) => String(d).slice(0, 120))
          : svc.requiredDocuments,
        availability: body.availability === 'Unavailable' ? 'Unavailable' : body.availability === 'Available' ? 'Available' : svc.availability,
        active: body.active !== undefined ? Boolean(body.active) : svc.active,
        moduleTag: svc.moduleTag,
        updatedBy: currentProfile.userId,
        updatedByUid: uid,
        createdAt: snap.exists() ? snap.data().createdAt : serverTimestamp(),
        updatedAt: serverTimestamp(),
      };
      await setDoc(ref, updatedDoc);
      return ok({ ...svc, ...updatedDoc, id: serviceId, updatedAt: new Date().toISOString() }) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `cscServiceOverrides/${serviceId}`);
    }
  }

  if (/^\/api\/csc\/services\/[^/]+\/rate$/.test(pathname) && method === 'PUT') {
    if (!isAdmin) errHttp('Forbidden: Only ADMIN can configure service rates.', 403);
    const serviceId = decodeURIComponent(pathname.split('/')[4] || '');
    const services = await loadMergedServices();
    const svc = services.find((s) => s.id === serviceId);
    if (!svc) errHttp('Service not found.', 404);

    const serviceCharge = round2(Number(body.serviceCharge));
    const govtFee = round2(Number(body.govtFee));
    const unitType = String(body.unitType || '') as UnitType;
    if (!Number.isFinite(serviceCharge) || serviceCharge < 0 || !Number.isFinite(govtFee) || govtFee < 0) {
      errHttp('Service Charge and Government Fee must be >= 0.', 422);
    }
    if (!ALL_UNIT_TYPES.includes(unitType)) errHttp('Invalid Unit Type.', 422);
    const totalAmount = round2(serviceCharge + govtFee);
    const effectiveDate = String(body.effectiveDate || new Date().toISOString().slice(0, 10));

    const ref = doc(db, 'cscServiceOverrides', serviceId);
    try {
      const snap = await getDoc(ref);
      await setDoc(ref, {
        serviceId,
        code: svc.code,
        categoryId: svc.categoryId,
        categoryName: svc.categoryName,
        subGroup: svc.subGroup || '',
        name: svc.name,
        description: svc.description,
        serviceCharge,
        govtFee,
        totalAmount,
        unitType,
        rateConfigured: true,
        effectiveDate,
        requiredDocuments: svc.requiredDocuments,
        availability: svc.availability,
        active: svc.active,
        moduleTag: svc.moduleTag,
        updatedBy: currentProfile.userId,
        updatedByUid: uid,
        createdAt: snap.exists() ? snap.data().createdAt : serverTimestamp(),
        updatedAt: serverTimestamp(),
      });

      const histId = `RATEH-${Date.now()}`;
      const histPayload: Omit<CscRateHistoryEntry, 'changedAt'> & {
        changedAt: string;
        createdByUid: string;
        createdAt: ReturnType<typeof serverTimestamp>;
      } = {
        id: histId,
        serviceId,
        serviceCode: svc.code,
        serviceName: svc.name,
        categoryName: svc.categoryName,
        adminId: currentProfile.userId,
        oldServiceCharge: svc.serviceCharge,
        newServiceCharge: serviceCharge,
        oldGovtFee: svc.govtFee,
        newGovtFee: govtFee,
        oldTotalAmount: svc.totalAmount,
        newTotalAmount: totalAmount,
        oldUnitType: svc.unitType,
        newUnitType: unitType,
        effectiveDate,
        changeReason: String(body.changeReason || 'Rate configuration updated'),
        changedAt: new Date().toISOString(),
        createdByUid: uid,
        createdAt: serverTimestamp(),
      };
      await setDoc(doc(db, 'cscRateHistory', histId), histPayload);

      return ok({
        service: {
          ...svc,
          serviceCharge,
          govtFee,
          totalAmount,
          unitType,
          rateConfigured: true,
          effectiveDate,
          updatedAt: new Date().toISOString(),
        },
        historyEntry: histPayload,
      }) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.WRITE, `cscServiceOverrides/${serviceId}`);
    }
  }

  if (pathname === '/api/csc/rate-history' && method === 'GET') {
    const raw = await listScopedDocs('cscRateHistory', uid, isBootAdmin);
    return ok(raw) as ApiResponseEnvelope<T>;
  }

  // =========================================================================
  // PVC PRINTING & WHOLESALE SHOPS
  // =========================================================================
  if (pathname === '/api/csc/pvc/card-types' && method === 'GET') {
    return ok(buildInitialPvcCardTypes()) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/csc/pvc/slabs' && method === 'GET') {
    if (isCustomer) errHttp('Forbidden.', 403);
    const mode = (searchParams.get('mode') || '').toUpperCase();
    const all = await loadMergedPvcSlabs();
    return ok(
      mode === 'INDIVIDUAL' || mode === 'WHOLESALE' ? all.filter((s) => s.mode === mode) : all
    ) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/csc/pvc/quote' && method === 'POST') {
    const mode = body.mode === 'WHOLESALE' ? 'WHOLESALE' : 'INDIVIDUAL';
    const slabs = await loadMergedPvcSlabs();
    const cardTypes = buildInitialPvcCardTypes();
    const rawItems = Array.isArray(body.items) ? (body.items as Array<{ cardTypeId: string; quantity: number }>) : [];
    const items: PvcOrderItem[] = rawItems.map((it, idx) => {
      const card = cardTypes.find((c) => c.id === it.cardTypeId);
      if (!card) errHttp(`Invalid cardTypeId at item ${idx + 1}`, 422);
      const qty = Number(it.quantity);
      const slab = slabs.find((s) => s.mode === mode && s.active && qty >= s.minQty && qty <= s.maxQty);
      if (!slab) errHttp(`No matching ${mode} PVC slab for ${qty} card(s).`, 422);
      return {
        lineId: `PVL-${idx + 1}`,
        cardTypeId: card.id,
        cardTypeName: card.name,
        quantity: qty,
        ratePerCard: slab.ratePerCard,
        lineTotal: round2(qty * slab.ratePerCard),
        slabId: slab.id,
      };
    });
    return ok({
      mode,
      items,
      totalCards: items.reduce((s, i) => s + i.quantity, 0),
      grandTotal: round2(items.reduce((s, i) => s + i.lineTotal, 0)),
    }) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/csc/pvc/slabs' && method === 'POST') {
    if (!isAdmin) errHttp('Only ADMIN can save PVC rate slabs.', 403);
    const mode = body.mode === 'WHOLESALE' ? 'WHOLESALE' : 'INDIVIDUAL';
    const minQty = Number(body.minQty);
    const maxQty = Number(body.maxQty);
    const ratePerCard = round2(Number(body.ratePerCard));
    if (!Number.isInteger(minQty) || minQty < 1 || !Number.isInteger(maxQty) || maxQty < minQty) {
      errHttp('Valid integer quantity range (Min >= 1, Max >= Min) required.', 422);
    }
    const existing = await loadMergedPvcSlabs();
    const conflict = existing.find(
      (s) => s.mode === mode && s.active && minQty <= s.maxQty && maxQty >= s.minQty
    );
    if (conflict) {
      errHttp(
        `Overlapping ${mode} PVC slab (${minQty}–${maxQty}) conflicts with existing slab (${conflict.minQty}–${conflict.maxQty}).`,
        422
      );
    }
    const id = `PVC-${mode === 'WHOLESALE' ? 'WHL' : 'IND'}-SLAB-${Date.now()}`;
    const docPayload = {
      id,
      mode,
      minQty,
      maxQty,
      ratePerCard,
      active: true,
      updatedBy: currentProfile.userId,
      createdByUid: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };
    try {
      await setDoc(doc(db, 'pvcSlabs', id), docPayload);
      return ok({ ...docPayload, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `pvcSlabs/${id}`);
    }
  }

  if (pathname.startsWith('/api/csc/pvc/slabs/') && method === 'DELETE') {
    if (!isAdmin) errHttp('Only ADMIN can delete PVC slabs.', 403);
    const id = decodeURIComponent(pathname.split('/').pop() || '');
    try {
      await deleteDoc(doc(db, 'pvcSlabs', id));
      return ok({ deleted: true }) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.DELETE, `pvcSlabs/${id}`);
    }
  }

  if (pathname === '/api/csc/pvc/shops' && method === 'GET') {
    if (isCustomer) errHttp('Forbidden.', 403);
    return ok(await listScopedDocs('wholesaleShops', uid, isBootAdmin)) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/csc/pvc/shops' && method === 'POST') {
    const id = `WSHOP-${Date.now()}`;
    const shopCode = `WSHP-${String(Date.now()).slice(-4)}`;
    const payload = {
      id,
      shopCode,
      shopName: String(body.shopName || '').trim(),
      ownerName: String(body.ownerName || '').trim(),
      mobile: String(body.mobile || '').trim(),
      altMobile: String(body.altMobile || ''),
      address: String(body.address || ''),
      registrationDate: new Date().toISOString().slice(0, 10),
      remarks: String(body.remarks || ''),
      active: true,
      createdByUid: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };
    try {
      await setDoc(doc(db, 'wholesaleShops', id), payload);
      return ok({ ...payload, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `wholesaleShops/${id}`);
    }
  }

  if (pathname === '/api/csc/pvc/orders' && method === 'GET') {
    return ok(await listScopedDocs('pvcOrders', uid, isBootAdmin, isCustomer)) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/csc/pvc/orders' && method === 'POST') {
    const mode = body.orderMode === 'WHOLESALE' ? 'WHOLESALE' : 'INDIVIDUAL';
    const slabs = await loadMergedPvcSlabs();
    const cardTypes = buildInitialPvcCardTypes();
    const rawItems = Array.isArray(body.items) ? (body.items as Array<{ cardTypeId: string; quantity: number }>) : [];
    if (rawItems.length === 0) errHttp('At least one PVC card item is required.', 422);

    const builtItems: PvcOrderItem[] = rawItems.map((it, idx) => {
      const card = cardTypes.find((c) => c.id === it.cardTypeId);
      if (!card) errHttp(`Invalid cardTypeId at item ${idx + 1}`, 422);
      const qty = Number(it.quantity);
      const slab = slabs.find((s) => s.mode === mode && s.active && qty >= s.minQty && qty <= s.maxQty);
      if (!slab) {
        errHttp(
          mode === 'WHOLESALE'
            ? `No matching wholesale PVC rate slab configured for ${qty} card(s). Admin must manually add a wholesale slab.`
            : `No matching individual PVC rate slab configured for ${qty} card(s).`,
          422
        );
      }
      return {
        lineId: `PVL-${idx + 1}`,
        cardTypeId: card.id,
        cardTypeName: card.name,
        quantity: qty,
        ratePerCard: slab.ratePerCard,
        lineTotal: round2(qty * slab.ratePerCard),
        slabId: slab.id,
      };
    });

    const totalCards = builtItems.reduce((s, i) => s + i.quantity, 0);
    const grandTotal = round2(builtItems.reduce((s, i) => s + i.lineTotal, 0));
    const advancePayment = round2(Math.max(0, Number(body.advancePayment ?? 0)));
    const orderId = `PVC-${mode === 'WHOLESALE' ? 'WHL' : 'IND'}-${Date.now().toString().slice(-6)}`;
    const nowIso = new Date().toISOString();
    const payments: CscPaymentEntry[] =
      advancePayment > 0
        ? [
            {
              receiptNumber: `CSCRCP-${Date.now().toString().slice(-6)}`,
              orderId,
              orderType: 'PVC_ORDER',
              customerName: String(body.customerName || 'Wholesale Partner'),
              mobile: String(body.mobile || ''),
              amount: advancePayment,
              paymentType: advancePayment >= grandTotal ? 'Full' : 'Advance',
              paymentMethod: String(body.paymentMethod || 'Cash'),
              paymentDate: nowIso.slice(0, 10),
              operatorId: currentProfile.userId,
              operatorName: currentProfile.fullName,
              remarks: String(body.remarks || ''),
              reprintCount: 0,
              createdAt: nowIso,
            },
          ]
        : [];

    const payload = {
      id: orderId,
      orderId,
      orderMode: mode,
      customerId: String(body.customerId || ''),
      customerName: String(body.customerName || 'Wholesale Shop'),
      mobile: String(body.mobile || ''),
      shopId: String(body.shopId || ''),
      shopName: String(body.shopName || ''),
      items: builtItems,
      totalCards,
      grandTotal,
      advancePayment,
      additionalPayments: 0,
      totalPaid: advancePayment,
      remainingDue: round2(Math.max(0, grandTotal - advancePayment)),
      paymentStatus: computePayStatus(grandTotal, advancePayment),
      deliveryStatus: 'Pending',
      orderDate: nowIso.slice(0, 10),
      operatorId: currentProfile.userId,
      operatorName: currentProfile.fullName,
      remarks: String(body.remarks || ''),
      payments,
      createdByUid: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };
    try {
      await setDoc(doc(db, 'pvcOrders', orderId), payload);
      return ok({ ...payload, createdAt: nowIso, updatedAt: nowIso }) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `pvcOrders/${orderId}`);
    }
  }

  // =========================================================================
  // CSC ORDERS, STATUSES, PAYMENTS, GRIEVANCES & DOCUMENTS
  // =========================================================================
  if (pathname === '/api/csc/orders' && method === 'GET') {
    return ok(await listScopedDocs('cscOrders', uid, isBootAdmin, isCustomer)) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/csc/orders' && method === 'POST') {
    const services = await loadMergedServices();
    const rawItems = Array.isArray(body.items) ? (body.items as Array<{ serviceId: string; quantity?: number }>) : [];
    if (rawItems.length === 0) errHttp('At least one service is required.', 422);

    const snapshots: CscOrderItemSnapshot[] = rawItems.map((line, idx) => {
      const svc = services.find((s) => s.id === line.serviceId);
      if (!svc) errHttp(`Service '${line.serviceId}' not found.`, 404);
      if (!svc.rateConfigured || svc.serviceCharge === null || svc.govtFee === null || !svc.unitType) {
        errHttp(`Rate is not configured for '${svc.name}'. Admin must configure Service Charge, Government Fee, and Unit Type before creating an order.`, 422);
      }
      const qty = Math.max(1, Math.floor(Number(line.quantity ?? 1)));
      const lineServiceCharge = round2(svc.serviceCharge * qty);
      const lineGovtFee = round2(svc.govtFee * qty);
      return {
        lineId: `ORDL-${idx + 1}`,
        categoryId: svc.categoryId,
        categoryName: svc.categoryName,
        serviceId: svc.id,
        serviceCode: svc.code,
        serviceName: svc.name,
        quantity: qty,
        unitType: svc.unitType,
        serviceChargeSnapshot: svc.serviceCharge,
        govtFeeSnapshot: svc.govtFee,
        unitTotalSnapshot: svc.totalAmount ?? round2(svc.serviceCharge + svc.govtFee),
        lineServiceCharge,
        lineGovtFee,
        lineTotal: round2(lineServiceCharge + lineGovtFee),
        rateEffectiveDate: svc.effectiveDate,
      };
    });

    const primary = snapshots[0];
    const primarySvc = services.find((s) => s.id === primary.serviceId)!;
    const serviceCharge = round2(snapshots.reduce((s, i) => s + i.lineServiceCharge, 0));
    const govtFee = round2(snapshots.reduce((s, i) => s + i.lineGovtFee, 0));
    const totalAmount = round2(serviceCharge + govtFee);
    const advancePayment = round2(Math.max(0, Number(body.advancePayment ?? 0)));
    const orderId = `CSC-ORD-${Date.now().toString().slice(-6)}`;
    const nowIso = new Date().toISOString();
    const payments: CscPaymentEntry[] =
      advancePayment > 0
        ? [
            {
              receiptNumber: `CSCRCP-${Date.now().toString().slice(-6)}`,
              orderId,
              orderType: 'CSC_ORDER',
              customerId: String(body.customerId || 'WALKIN'),
              customerName: String(body.customerName || 'Citizen'),
              mobile: String(body.mobile || ''),
              amount: advancePayment,
              paymentType: advancePayment >= totalAmount ? 'Full' : 'Advance',
              paymentMethod: String(body.paymentMethod || 'Cash'),
              paymentDate: nowIso.slice(0, 10),
              operatorId: currentProfile.userId,
              operatorName: currentProfile.fullName,
              remarks: String(body.adminRemarks || ''),
              reprintCount: 0,
              createdAt: nowIso,
            },
          ]
        : [];

    const payload = {
      id: orderId,
      orderId,
      customerId: String(body.customerId || 'WALKIN'),
      customerUid: '',
      customerName: maskAadhaarStr(String(body.customerName || 'Citizen')),
      mobile: String(body.mobile || ''),
      selectedCategoryId: primary.categoryId,
      selectedCategoryName: primary.categoryName,
      selectedServiceId: primary.serviceId,
      selectedServiceName: primary.serviceName,
      items: snapshots,
      applicationDetails: (body.applicationDetails as Record<string, string>) || {},
      documents: [],
      serviceCharge,
      govtFee,
      totalAmount,
      advancePayment,
      additionalPayments: 0,
      refundedAmount: 0,
      totalPaid: advancePayment,
      remainingDue: round2(Math.max(0, totalAmount - advancePayment)),
      orderDate: nowIso.slice(0, 10),
      applicationStatus: 'Pending' as CscApplicationStatus,
      paymentStatus: computePayStatus(totalAmount, advancePayment),
      operatorId: currentProfile.userId,
      operatorName: currentProfile.fullName,
      adminRemarks: String(body.adminRemarks || ''),
      moduleTag: primarySvc.moduleTag,
      payments,
      statusHistory: [
        {
          id: `STH-${Date.now()}`,
          previousStatus: null,
          newStatus: 'Pending',
          changedBy: currentProfile.userId,
          remarks: 'Order created with immutable rate snapshot.',
          changedAt: nowIso,
        },
      ],
      createdByUid: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };
    try {
      await setDoc(doc(db, 'cscOrders', orderId), payload);
      return ok({ ...payload, createdAt: nowIso, updatedAt: nowIso }) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `cscOrders/${orderId}`);
    }
  }

  if (/^\/api\/csc\/orders\/[^/]+\/status$/.test(pathname) && method === 'PATCH') {
    const orderId = decodeURIComponent(pathname.split('/')[4] || '');
    const ref = doc(db, 'cscOrders', orderId);
    try {
      const snap = await getDoc(ref);
      if (!snap.exists()) errHttp('Order not found.', 404);
      const data = snap.data();
      const statusHistory = Array.isArray(data.statusHistory) ? data.statusHistory : [];
      const nextStatus = String(body.status) as CscApplicationStatus;
      statusHistory.unshift({
        id: `STH-${Date.now()}`,
        previousStatus: data.applicationStatus,
        newStatus: nextStatus,
        changedBy: currentProfile.userId,
        remarks: String(body.remarks || ''),
        changedAt: new Date().toISOString(),
      });
      await updateDoc(ref, {
        applicationStatus: nextStatus,
        statusHistory,
        updatedAt: serverTimestamp(),
      });
      return ok({ ...data, applicationStatus: nextStatus, statusHistory }) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `cscOrders/${orderId}`);
    }
  }

  if (pathname === '/api/csc/grievances' && method === 'GET') {
    return ok(await listScopedDocs('cscGrievances', uid, isBootAdmin, isCustomer)) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/csc/grievances' && method === 'POST') {
    const trackingId = `GRV-${Date.now().toString().slice(-6)}`;
    const nowIso = new Date().toISOString();
    const sc = round2(Math.max(0, Number(body.serviceCharge ?? 0)));
    const gf = round2(Math.max(0, Number(body.govtFee ?? 0)));
    const total = round2(sc + gf);
    const paid = round2(Math.max(0, Number(body.paidAmount ?? 0)));
    const payload = {
      id: trackingId,
      internalTrackingId: trackingId,
      externalAckNo: String(body.externalAckNo || ''),
      customerId: String(body.customerId || ''),
      customerUid: isCustomer ? uid : '',
      customerName: String(body.customerName || currentProfile.fullName),
      mobile: String(body.mobile || currentProfile.mobile),
      address: String(body.address || ''),
      district: String(body.district || 'North 24 Parganas'),
      blockOrMunicipality: String(body.blockOrMunicipality || ''),
      complaintCategory: String(body.complaintCategory || 'General'),
      serviceType: String(body.serviceType || 'Application Drafting'),
      department: String(body.department || 'General Administration'),
      authority: String(body.authority || 'Public Grievance Officer'),
      complaintSubject: String(body.complaintSubject || 'Citizen Grievance'),
      complaintDetails: maskAadhaarStr(String(body.complaintDetails || '')),
      uploadedDocuments: [],
      serviceCharge: sc,
      govtFee: gf,
      totalAmount: total,
      paidAmount: paid,
      remainingDue: round2(Math.max(0, total - paid)),
      paymentStatus: computePayStatus(total, paid),
      submissionDate: nowIso.slice(0, 10),
      followUpDate: String(body.followUpDate || nowIso.slice(0, 10)),
      complaintStatus: 'Submitted' as GrievanceStatus,
      isRti: Boolean(body.isRti),
      adminRemarks: String(body.adminRemarks || ''),
      operatorId: currentProfile.userId,
      operatorName: currentProfile.fullName,
      followUps: [],
      statusHistory: [],
      createdByUid: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };
    try {
      await setDoc(doc(db, 'cscGrievances', trackingId), payload);
      return ok({ ...payload, createdAt: nowIso, updatedAt: nowIso }) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `cscGrievances/${trackingId}`);
    }
  }

  if (pathname === '/api/csc/documents' && method === 'GET') {
    return ok(await listScopedDocs('cscDocuments', uid, isBootAdmin, isCustomer)) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/csc/documents' && method === 'POST') {
    const docId = `CSCDOC-${Date.now().toString().slice(-6)}`;
    const nowIso = new Date().toISOString();
    const payload: Record<string, unknown> = {
      docId,
      customerId: String(body.customerId || 'WALKIN'),
      customerUid: isCustomer ? uid : '',
      orderId: String(body.orderId || ''),
      grievanceId: String(body.grievanceId || ''),
      category: String(body.category || 'Supporting Proof'),
      docName: maskAadhaarStr(String(body.docName || 'Document')),
      mimeType: String(body.mimeType || 'application/pdf'),
      fileSizeBytes: Number(body.fileSizeBytes ?? 0),
      verificationStatus: 'Pending',
      uploadedBy: currentProfile.userId,
      uploadedAt: nowIso,
      auditTrail: [
        {
          id: `DA-${Date.now()}`,
          action: 'UPLOADED',
          actorId: currentProfile.userId,
          note: 'Uploaded to private Firestore document vault.',
          at: nowIso,
        },
      ],
      createdByUid: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };
    try {
      await setDoc(doc(db, 'cscDocuments', docId), payload);
      return ok({ ...payload, createdAt: nowIso, updatedAt: nowIso } as unknown as CscDocumentRecord) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `cscDocuments/${docId}`);
    }
  }

  if (pathname === '/api/csc/payment-methods' && method === 'GET') {
    return ok([
      { id: 'PM-CASH', name: 'Cash', active: true },
      { id: 'PM-UPI', name: 'UPI', active: true },
      { id: 'PM-BANK', name: 'Bank Transfer', active: true },
    ]) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/csc/receipts' && method === 'GET') {
    const [orders, pvcOrders] = await Promise.all([
      listScopedDocs('cscOrders', uid, isBootAdmin, isCustomer),
      listScopedDocs('pvcOrders', uid, isBootAdmin, isCustomer),
    ]);
    const receipts = [
      ...orders.flatMap((o) => (Array.isArray(o.payments) ? o.payments : [])),
      ...pvcOrders.flatMap((o) => (Array.isArray(o.payments) ? o.payments : [])),
    ];
    return ok(receipts) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/csc/portal/me' && method === 'GET') {
    const [orders, pvcOrders, grievances, documents] = await Promise.all([
      listScopedDocs('cscOrders', uid, isBootAdmin, isCustomer),
      listScopedDocs('pvcOrders', uid, isBootAdmin, isCustomer),
      listScopedDocs('cscGrievances', uid, isBootAdmin, isCustomer),
      listScopedDocs('cscDocuments', uid, isBootAdmin, isCustomer),
    ]);
    return ok({
      customer: {
        customerId: currentProfile.userId,
        fullName: currentProfile.fullName,
        mobile: currentProfile.mobile,
        address: currentProfile.address,
      },
      orders,
      pvcOrders,
      grievances,
      documents,
      receipts: [
        ...orders.flatMap((o) => (Array.isArray(o.payments) ? o.payments : [])),
        ...pvcOrders.flatMap((o) => (Array.isArray(o.payments) ? o.payments : [])),
      ],
    }) as ApiResponseEnvelope<T>;
  }

  return null;
}

function computeKpisFromArrays(
  categories: CscCategory[],
  services: CscService[],
  customers: unknown[],
  orders: CscOrderRecord[],
  pvcOrders: PvcOrder[],
  grievances: GrievanceRecord[],
  fromDate?: string,
  toDate?: string
): CscAdminDashboardKpis {
  const inRange = (dStr = '') => {
    const iso = dStr.slice(0, 10);
    if (fromDate && iso < fromDate) return false;
    if (toDate && iso > toDate) return false;
    return true;
  };
  const fOrders = orders.filter((o) => inRange(o.orderDate || ''));
  const fPvc = pvcOrders.filter((p) => inRange(p.orderDate || ''));
  const fGrv = grievances.filter((g) => inRange(g.submissionDate || ''));
  const todayIso = new Date().toISOString().slice(0, 10);
  const monthPrefix = todayIso.slice(0, 7);

  const totalSales = round2(
    fOrders.reduce((s, o) => s + Number(o.totalAmount || 0), 0) +
      fPvc.reduce((s, p) => s + Number(p.grandTotal || 0), 0) +
      fGrv.reduce((s, g) => s + Number(g.totalAmount || 0), 0)
  );
  const totalCollection = round2(
    fOrders.reduce((s, o) => s + Number(o.totalPaid || 0), 0) +
      fPvc.reduce((s, p) => s + Number(p.totalPaid || 0), 0) +
      fGrv.reduce((s, g) => s + Number(g.paidAmount || 0), 0)
  );
  const totalDue = round2(
    fOrders.reduce((s, o) => s + Number(o.remainingDue || 0), 0) +
      fPvc.reduce((s, p) => s + Number(p.remainingDue || 0), 0) +
      fGrv.reduce((s, g) => s + Number(g.remainingDue || 0), 0)
  );

  return {
    totalCustomers: customers.length,
    totalCategories: categories.length,
    totalServices: services.length,
    activeServices: services.filter((s) => s.active).length,
    inactiveServices: services.filter((s) => !s.active).length,
    totalOrders: fOrders.length + fPvc.length,
    pendingApplications: fOrders.filter((o) => ['Draft', 'Pending', 'Document Required', 'e-KYC Pending'].includes(o.applicationStatus)).length,
    processingApplications: fOrders.filter((o) => !['Draft', 'Pending', 'Document Required', 'e-KYC Pending', 'Completed', 'Delivered', 'Cancelled', 'Rejected'].includes(o.applicationStatus)).length,
    completedApplications: fOrders.filter((o) => o.applicationStatus === 'Completed' || o.applicationStatus === 'Delivered').length,
    totalSales,
    totalCollection,
    totalDue,
    todaysSales: round2(fOrders.filter((o) => o.orderDate === todayIso).reduce((s, o) => s + Number(o.totalAmount || 0), 0)),
    monthlySales: round2(fOrders.filter((o) => (o.orderDate || '').startsWith(monthPrefix)).reduce((s, o) => s + Number(o.totalAmount || 0), 0)),
    pvcIndividualOrders: fPvc.filter((p) => p.orderMode === 'INDIVIDUAL').length,
    pvcWholesaleOrders: fPvc.filter((p) => p.orderMode === 'WHOLESALE').length,
    totalPvcCardsPrinted: fPvc.reduce((s, p) => s + Number(p.totalCards || 0), 0),
    pvcPendingOrders: fPvc.filter((p) => p.deliveryStatus === 'Pending' || p.deliveryStatus === 'Printing').length,
    totalGrievances: fGrv.length,
    pendingGrievances: fGrv.filter((g) => !['Resolved', 'Rejected', 'Closed'].includes(g.complaintStatus)).length,
    mmsbyOrders: fOrders.filter((o) => o.moduleTag === 'MMSBY').length,
    ayushmanBharatOrders: fOrders.filter((o) => o.moduleTag === 'PMJAY').length,
    ekycPending: fOrders.filter((o) => o.ekycStatus === 'Pending').length,
    ekycCompleted: fOrders.filter((o) => o.ekycStatus === 'Completed').length,
    statusBreakdown: {},
    dailySalesTrend: [],
    categoryBreakdown: [],
  };
}
